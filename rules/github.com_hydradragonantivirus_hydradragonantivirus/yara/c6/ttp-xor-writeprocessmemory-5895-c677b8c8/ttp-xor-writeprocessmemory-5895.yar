rule TTP_XOR_WriteProcessMemory_5895 {
  strings:
    $key_5895 = { 0f e7 [2] 3d c5 [2] 3b f0 [2] 15 f0 [2] 2a ec }

  condition:
    any of them
}