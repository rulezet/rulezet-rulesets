rule TTP_XOR_WriteProcessMemory_e543 {
  strings:
    $key_e543 = { b2 31 [2] 80 13 [2] 86 26 [2] a8 26 [2] 97 3a }

  condition:
    any of them
}