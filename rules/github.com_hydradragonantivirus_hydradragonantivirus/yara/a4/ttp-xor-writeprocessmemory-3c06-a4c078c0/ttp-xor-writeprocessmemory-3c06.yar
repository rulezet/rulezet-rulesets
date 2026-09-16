rule TTP_XOR_WriteProcessMemory_3c06 {
  strings:
    $key_3c06 = { 6b 74 [2] 59 56 [2] 5f 63 [2] 71 63 [2] 4e 7f }

  condition:
    any of them
}