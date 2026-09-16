rule TTP_XOR_WriteProcessMemory_f679 {
  strings:
    $key_f679 = { a1 0b [2] 93 29 [2] 95 1c [2] bb 1c [2] 84 00 }

  condition:
    any of them
}