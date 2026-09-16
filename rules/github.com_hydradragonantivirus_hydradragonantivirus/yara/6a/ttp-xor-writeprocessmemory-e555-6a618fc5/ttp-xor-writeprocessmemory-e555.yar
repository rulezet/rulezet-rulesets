rule TTP_XOR_WriteProcessMemory_e555 {
  strings:
    $key_e555 = { b2 27 [2] 80 05 [2] 86 30 [2] a8 30 [2] 97 2c }

  condition:
    any of them
}