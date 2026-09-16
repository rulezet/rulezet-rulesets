rule TTP_XOR_WriteProcessMemory_1ee2 {
  strings:
    $key_1ee2 = { 49 90 [2] 7b b2 [2] 7d 87 [2] 53 87 [2] 6c 9b }

  condition:
    any of them
}