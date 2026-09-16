rule TTP_XOR_WriteProcessMemory_3895 {
  strings:
    $key_3895 = { 6f e7 [2] 5d c5 [2] 5b f0 [2] 75 f0 [2] 4a ec }

  condition:
    any of them
}