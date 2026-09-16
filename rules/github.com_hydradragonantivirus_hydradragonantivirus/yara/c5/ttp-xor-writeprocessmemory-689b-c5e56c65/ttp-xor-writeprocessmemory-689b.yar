rule TTP_XOR_WriteProcessMemory_689b {
  strings:
    $key_689b = { 3f e9 [2] 0d cb [2] 0b fe [2] 25 fe [2] 1a e2 }

  condition:
    any of them
}