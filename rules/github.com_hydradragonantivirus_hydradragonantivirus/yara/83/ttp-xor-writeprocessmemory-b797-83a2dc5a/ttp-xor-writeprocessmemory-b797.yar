rule TTP_XOR_WriteProcessMemory_b797 {
  strings:
    $key_b797 = { e0 e5 [2] d2 c7 [2] d4 f2 [2] fa f2 [2] c5 ee }

  condition:
    any of them
}