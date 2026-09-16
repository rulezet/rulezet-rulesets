rule TTP_XOR_WriteProcessMemory_d095 {
  strings:
    $key_d095 = { 87 e7 [2] b5 c5 [2] b3 f0 [2] 9d f0 [2] a2 ec }

  condition:
    any of them
}