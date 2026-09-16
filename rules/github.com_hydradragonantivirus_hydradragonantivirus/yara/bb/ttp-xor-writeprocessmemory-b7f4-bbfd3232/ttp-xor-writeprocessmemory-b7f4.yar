rule TTP_XOR_WriteProcessMemory_b7f4 {
  strings:
    $key_b7f4 = { e0 86 [2] d2 a4 [2] d4 91 [2] fa 91 [2] c5 8d }

  condition:
    any of them
}