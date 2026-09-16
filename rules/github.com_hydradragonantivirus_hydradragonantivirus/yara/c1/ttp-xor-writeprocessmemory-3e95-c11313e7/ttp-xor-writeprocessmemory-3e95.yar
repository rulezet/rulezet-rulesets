rule TTP_XOR_WriteProcessMemory_3e95 {
  strings:
    $key_3e95 = { 69 e7 [2] 5b c5 [2] 5d f0 [2] 73 f0 [2] 4c ec }

  condition:
    any of them
}