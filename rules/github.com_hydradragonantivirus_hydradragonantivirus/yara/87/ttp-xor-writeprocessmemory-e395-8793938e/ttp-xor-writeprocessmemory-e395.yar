rule TTP_XOR_WriteProcessMemory_e395 {
  strings:
    $key_e395 = { b4 e7 [2] 86 c5 [2] 80 f0 [2] ae f0 [2] 91 ec }

  condition:
    any of them
}