rule TTP_XOR_WriteProcessMemory_b745 {
  strings:
    $key_b745 = { e0 37 [2] d2 15 [2] d4 20 [2] fa 20 [2] c5 3c }

  condition:
    any of them
}