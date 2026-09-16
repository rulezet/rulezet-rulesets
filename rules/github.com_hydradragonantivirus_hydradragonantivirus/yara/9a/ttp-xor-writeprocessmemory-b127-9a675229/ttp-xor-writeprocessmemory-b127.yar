rule TTP_XOR_WriteProcessMemory_b127 {
  strings:
    $key_b127 = { e6 55 [2] d4 77 [2] d2 42 [2] fc 42 [2] c3 5e }

  condition:
    any of them
}