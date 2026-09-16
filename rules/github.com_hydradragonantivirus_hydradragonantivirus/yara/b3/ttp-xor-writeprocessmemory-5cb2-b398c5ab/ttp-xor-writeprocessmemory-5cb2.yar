rule TTP_XOR_WriteProcessMemory_5cb2 {
  strings:
    $key_5cb2 = { 0b c0 [2] 39 e2 [2] 3f d7 [2] 11 d7 [2] 2e cb }

  condition:
    any of them
}