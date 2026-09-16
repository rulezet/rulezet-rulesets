rule TTP_XOR_WriteProcessMemory_389b {
  strings:
    $key_389b = { 6f e9 [2] 5d cb [2] 5b fe [2] 75 fe [2] 4a e2 }

  condition:
    any of them
}