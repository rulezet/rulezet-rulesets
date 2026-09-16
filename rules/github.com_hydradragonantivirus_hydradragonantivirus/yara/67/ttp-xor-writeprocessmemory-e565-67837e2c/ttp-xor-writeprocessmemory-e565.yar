rule TTP_XOR_WriteProcessMemory_e565 {
  strings:
    $key_e565 = { b2 17 [2] 80 35 [2] 86 00 [2] a8 00 [2] 97 1c }

  condition:
    any of them
}