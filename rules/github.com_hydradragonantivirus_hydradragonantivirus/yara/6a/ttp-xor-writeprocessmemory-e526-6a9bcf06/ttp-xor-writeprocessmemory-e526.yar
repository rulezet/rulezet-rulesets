rule TTP_XOR_WriteProcessMemory_e526 {
  strings:
    $key_e526 = { b2 54 [2] 80 76 [2] 86 43 [2] a8 43 [2] 97 5f }

  condition:
    any of them
}