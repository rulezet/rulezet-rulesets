rule TTP_XOR_WriteProcessMemory_6ce2 {
  strings:
    $key_6ce2 = { 3b 90 [2] 09 b2 [2] 0f 87 [2] 21 87 [2] 1e 9b }

  condition:
    any of them
}