rule TTP_XOR_WriteProcessMemory_ee95 {
  strings:
    $key_ee95 = { b9 e7 [2] 8b c5 [2] 8d f0 [2] a3 f0 [2] 9c ec }

  condition:
    any of them
}