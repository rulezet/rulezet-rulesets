rule TTP_XOR_WriteProcessMemory_b7e5 {
  strings:
    $key_b7e5 = { e0 97 [2] d2 b5 [2] d4 80 [2] fa 80 [2] c5 9c }

  condition:
    any of them
}