rule TTP_XOR_WriteProcessMemory_69f2 {
  strings:
    $key_69f2 = { 3e 80 [2] 0c a2 [2] 0a 97 [2] 24 97 [2] 1b 8b }

  condition:
    any of them
}