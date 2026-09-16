rule TTP_XOR_WriteProcessMemory_f655 {
  strings:
    $key_f655 = { a1 27 [2] 93 05 [2] 95 30 [2] bb 30 [2] 84 2c }

  condition:
    any of them
}