rule TTP_XOR_WriteProcessMemory_5de2 {
  strings:
    $key_5de2 = { 0a 90 [2] 38 b2 [2] 3e 87 [2] 10 87 [2] 2f 9b }

  condition:
    any of them
}