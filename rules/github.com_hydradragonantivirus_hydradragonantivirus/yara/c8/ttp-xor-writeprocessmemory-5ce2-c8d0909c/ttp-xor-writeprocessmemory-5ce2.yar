rule TTP_XOR_WriteProcessMemory_5ce2 {
  strings:
    $key_5ce2 = { 0b 90 [2] 39 b2 [2] 3f 87 [2] 11 87 [2] 2e 9b }

  condition:
    any of them
}