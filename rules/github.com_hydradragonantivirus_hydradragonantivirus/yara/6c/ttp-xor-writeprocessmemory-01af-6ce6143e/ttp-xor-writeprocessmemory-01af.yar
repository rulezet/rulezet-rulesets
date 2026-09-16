rule TTP_XOR_WriteProcessMemory_01af {
  strings:
    $key_01af = { 56 dd [2] 64 ff [2] 62 ca [2] 4c ca [2] 73 d6 }

  condition:
    any of them
}