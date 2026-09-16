rule TTP_XOR_WriteProcessMemory_f556 {
  strings:
    $key_f556 = { a2 24 [2] 90 06 [2] 96 33 [2] b8 33 [2] 87 2f }

  condition:
    any of them
}