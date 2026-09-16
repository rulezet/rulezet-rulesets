rule TTP_XOR_WriteProcessMemory_e605 {
  strings:
    $key_e605 = { b1 77 [2] 83 55 [2] 85 60 [2] ab 60 [2] 94 7c }

  condition:
    any of them
}