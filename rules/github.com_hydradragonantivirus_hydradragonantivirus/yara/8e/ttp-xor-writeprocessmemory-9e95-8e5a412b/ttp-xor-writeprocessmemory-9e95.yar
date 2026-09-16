rule TTP_XOR_WriteProcessMemory_9e95 {
  strings:
    $key_9e95 = { c9 e7 [2] fb c5 [2] fd f0 [2] d3 f0 [2] ec ec }

  condition:
    any of them
}