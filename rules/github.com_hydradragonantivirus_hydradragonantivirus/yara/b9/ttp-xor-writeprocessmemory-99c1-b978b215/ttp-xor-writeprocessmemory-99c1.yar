rule TTP_XOR_WriteProcessMemory_99c1 {
  strings:
    $key_99c1 = { ce b3 [2] fc 91 [2] fa a4 [2] d4 a4 [2] eb b8 }

  condition:
    any of them
}