rule TTP_XOR_WriteProcessMemory_f555 {
  strings:
    $key_f555 = { a2 27 [2] 90 05 [2] 96 30 [2] b8 30 [2] 87 2c }

  condition:
    any of them
}