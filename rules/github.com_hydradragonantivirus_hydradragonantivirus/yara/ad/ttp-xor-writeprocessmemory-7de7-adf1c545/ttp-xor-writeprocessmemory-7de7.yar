rule TTP_XOR_WriteProcessMemory_7de7 {
  strings:
    $key_7de7 = { 2a 95 [2] 18 b7 [2] 1e 82 [2] 30 82 [2] 0f 9e }

  condition:
    any of them
}