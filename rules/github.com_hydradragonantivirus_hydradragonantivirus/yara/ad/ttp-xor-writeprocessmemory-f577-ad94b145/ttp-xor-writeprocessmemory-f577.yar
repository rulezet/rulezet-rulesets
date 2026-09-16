rule TTP_XOR_WriteProcessMemory_f577 {
  strings:
    $key_f577 = { a2 05 [2] 90 27 [2] 96 12 [2] b8 12 [2] 87 0e }

  condition:
    any of them
}