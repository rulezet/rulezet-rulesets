rule TTP_XOR_WriteProcessMemory_7de2 {
  strings:
    $key_7de2 = { 2a 90 [2] 18 b2 [2] 1e 87 [2] 30 87 [2] 0f 9b }

  condition:
    any of them
}