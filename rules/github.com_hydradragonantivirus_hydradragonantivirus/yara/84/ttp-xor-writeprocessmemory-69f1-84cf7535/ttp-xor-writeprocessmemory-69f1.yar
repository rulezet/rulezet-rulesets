rule TTP_XOR_WriteProcessMemory_69f1 {
  strings:
    $key_69f1 = { 3e 83 [2] 0c a1 [2] 0a 94 [2] 24 94 [2] 1b 88 }

  condition:
    any of them
}