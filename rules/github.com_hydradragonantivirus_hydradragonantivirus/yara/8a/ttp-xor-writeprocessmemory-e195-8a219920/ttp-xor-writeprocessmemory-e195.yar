rule TTP_XOR_WriteProcessMemory_e195 {
  strings:
    $key_e195 = { b6 e7 [2] 84 c5 [2] 82 f0 [2] ac f0 [2] 93 ec }

  condition:
    any of them
}