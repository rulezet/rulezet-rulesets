rule TTP_XOR_WriteProcessMemory_789b {
  strings:
    $key_789b = { 2f e9 [2] 1d cb [2] 1b fe [2] 35 fe [2] 0a e2 }

  condition:
    any of them
}