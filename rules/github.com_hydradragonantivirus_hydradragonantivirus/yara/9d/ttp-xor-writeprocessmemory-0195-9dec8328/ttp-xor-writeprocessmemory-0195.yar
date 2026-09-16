rule TTP_XOR_WriteProcessMemory_0195 {
  strings:
    $key_0195 = { 56 e7 [2] 64 c5 [2] 62 f0 [2] 4c f0 [2] 73 ec }

  condition:
    any of them
}