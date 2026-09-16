rule TTP_XOR_WriteProcessMemory_9995 {
  strings:
    $key_9995 = { ce e7 [2] fc c5 [2] fa f0 [2] d4 f0 [2] eb ec }

  condition:
    any of them
}