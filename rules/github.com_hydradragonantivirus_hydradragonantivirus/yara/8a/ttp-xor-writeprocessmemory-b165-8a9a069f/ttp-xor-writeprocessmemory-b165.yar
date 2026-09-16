rule TTP_XOR_WriteProcessMemory_b165 {
  strings:
    $key_b165 = { e6 17 [2] d4 35 [2] d2 00 [2] fc 00 [2] c3 1c }

  condition:
    any of them
}