rule TTP_XOR_WriteProcessMemory_f624 {
  strings:
    $key_f624 = { a1 56 [2] 93 74 [2] 95 41 [2] bb 41 [2] 84 5d }

  condition:
    any of them
}