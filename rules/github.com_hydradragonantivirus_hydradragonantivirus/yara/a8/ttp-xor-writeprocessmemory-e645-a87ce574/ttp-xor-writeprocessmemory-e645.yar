rule TTP_XOR_WriteProcessMemory_e645 {
  strings:
    $key_e645 = { b1 37 [2] 83 15 [2] 85 20 [2] ab 20 [2] 94 3c }

  condition:
    any of them
}