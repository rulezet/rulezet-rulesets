rule TTP_XOR_WriteProcessMemory_b135 {
  strings:
    $key_b135 = { e6 47 [2] d4 65 [2] d2 50 [2] fc 50 [2] c3 4c }

  condition:
    any of them
}