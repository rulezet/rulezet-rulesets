rule TTP_XOR_WriteProcessMemory_a195 {
  strings:
    $key_a195 = { f6 e7 [2] c4 c5 [2] c2 f0 [2] ec f0 [2] d3 ec }

  condition:
    any of them
}