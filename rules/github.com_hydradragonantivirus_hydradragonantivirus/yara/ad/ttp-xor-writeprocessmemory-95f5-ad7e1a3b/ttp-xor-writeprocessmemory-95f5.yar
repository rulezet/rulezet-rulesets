rule TTP_XOR_WriteProcessMemory_95f5 {
  strings:
    $key_95f5 = { c2 87 [2] f0 a5 [2] f6 90 [2] d8 90 [2] e7 8c }

  condition:
    any of them
}