rule TTP_XOR_WriteProcessMemory_69f6 {
  strings:
    $key_69f6 = { 3e 84 [2] 0c a6 [2] 0a 93 [2] 24 93 [2] 1b 8f }

  condition:
    any of them
}