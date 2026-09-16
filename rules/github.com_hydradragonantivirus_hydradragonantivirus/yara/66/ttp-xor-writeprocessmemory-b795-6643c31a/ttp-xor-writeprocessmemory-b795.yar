rule TTP_XOR_WriteProcessMemory_b795 {
  strings:
    $key_b795 = { e0 e7 [2] d2 c5 [2] d4 f0 [2] fa f0 [2] c5 ec }

  condition:
    any of them
}