rule TTP_XOR_WriteProcessMemory_66af {
  strings:
    $key_66af = { 31 dd [2] 03 ff [2] 05 ca [2] 2b ca [2] 14 d6 }

  condition:
    any of them
}