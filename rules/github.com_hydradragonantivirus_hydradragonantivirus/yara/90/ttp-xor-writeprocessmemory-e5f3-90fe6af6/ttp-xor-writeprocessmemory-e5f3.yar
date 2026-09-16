rule TTP_XOR_WriteProcessMemory_e5f3 {
  strings:
    $key_e5f3 = { b2 81 [2] 80 a3 [2] 86 96 [2] a8 96 [2] 97 8a }

  condition:
    any of them
}