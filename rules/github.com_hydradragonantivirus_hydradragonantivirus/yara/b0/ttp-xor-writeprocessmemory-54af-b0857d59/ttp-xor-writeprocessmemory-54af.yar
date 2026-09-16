rule TTP_XOR_WriteProcessMemory_54af {
  strings:
    $key_54af = { 03 dd [2] 31 ff [2] 37 ca [2] 19 ca [2] 26 d6 }

  condition:
    any of them
}