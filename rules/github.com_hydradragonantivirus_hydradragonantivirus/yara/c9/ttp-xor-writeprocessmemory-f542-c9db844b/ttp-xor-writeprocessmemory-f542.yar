rule TTP_XOR_WriteProcessMemory_f542 {
  strings:
    $key_f542 = { a2 30 [2] 90 12 [2] 96 27 [2] b8 27 [2] 87 3b }

  condition:
    any of them
}