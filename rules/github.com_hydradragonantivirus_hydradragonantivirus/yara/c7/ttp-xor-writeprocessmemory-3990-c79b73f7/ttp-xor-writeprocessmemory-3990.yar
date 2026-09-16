rule TTP_XOR_WriteProcessMemory_3990 {
  strings:
    $key_3990 = { 6e e2 [2] 5c c0 [2] 5a f5 [2] 74 f5 [2] 4b e9 }

  condition:
    any of them
}