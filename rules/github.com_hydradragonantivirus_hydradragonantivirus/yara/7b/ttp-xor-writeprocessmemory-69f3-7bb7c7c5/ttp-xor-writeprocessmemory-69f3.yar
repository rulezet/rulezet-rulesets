rule TTP_XOR_WriteProcessMemory_69f3 {
  strings:
    $key_69f3 = { 3e 81 [2] 0c a3 [2] 0a 96 [2] 24 96 [2] 1b 8a }

  condition:
    any of them
}