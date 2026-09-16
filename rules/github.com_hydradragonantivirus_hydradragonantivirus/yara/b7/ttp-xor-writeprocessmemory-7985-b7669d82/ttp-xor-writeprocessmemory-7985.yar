rule TTP_XOR_WriteProcessMemory_7985 {
  strings:
    $key_7985 = { 2e f7 [2] 1c d5 [2] 1a e0 [2] 34 e0 [2] 0b fc }

  condition:
    any of them
}