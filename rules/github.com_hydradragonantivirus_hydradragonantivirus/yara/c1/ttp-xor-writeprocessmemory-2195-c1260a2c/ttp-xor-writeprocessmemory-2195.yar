rule TTP_XOR_WriteProcessMemory_2195 {
  strings:
    $key_2195 = { 76 e7 [2] 44 c5 [2] 42 f0 [2] 6c f0 [2] 53 ec }

  condition:
    any of them
}