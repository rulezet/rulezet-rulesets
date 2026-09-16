rule TTP_XOR_WriteProcessMemory_b105 {
  strings:
    $key_b105 = { e6 77 [2] d4 55 [2] d2 60 [2] fc 60 [2] c3 7c }

  condition:
    any of them
}