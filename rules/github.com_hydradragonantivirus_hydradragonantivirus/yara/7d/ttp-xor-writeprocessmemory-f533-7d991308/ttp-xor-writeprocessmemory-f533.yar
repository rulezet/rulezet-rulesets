rule TTP_XOR_WriteProcessMemory_f533 {
  strings:
    $key_f533 = { a2 41 [2] 90 63 [2] 96 56 [2] b8 56 [2] 87 4a }

  condition:
    any of them
}