rule TTP_XOR_WriteProcessMemory_be95 {
  strings:
    $key_be95 = { e9 e7 [2] db c5 [2] dd f0 [2] f3 f0 [2] cc ec }

  condition:
    any of them
}