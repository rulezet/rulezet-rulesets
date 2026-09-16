rule TTP_XOR_WriteProcessMemory_089b {
  strings:
    $key_089b = { 5f e9 [2] 6d cb [2] 6b fe [2] 45 fe [2] 7a e2 }

  condition:
    any of them
}