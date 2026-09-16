rule TTP_XOR_WriteProcessMemory_5d06 {
  strings:
    $key_5d06 = { 0a 74 [2] 38 56 [2] 3e 63 [2] 10 63 [2] 2f 7f }

  condition:
    any of them
}