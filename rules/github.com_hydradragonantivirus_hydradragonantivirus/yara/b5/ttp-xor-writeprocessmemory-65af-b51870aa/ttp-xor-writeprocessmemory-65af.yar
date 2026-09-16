rule TTP_XOR_WriteProcessMemory_65af {
  strings:
    $key_65af = { 32 dd [2] 00 ff [2] 06 ca [2] 28 ca [2] 17 d6 }

  condition:
    any of them
}