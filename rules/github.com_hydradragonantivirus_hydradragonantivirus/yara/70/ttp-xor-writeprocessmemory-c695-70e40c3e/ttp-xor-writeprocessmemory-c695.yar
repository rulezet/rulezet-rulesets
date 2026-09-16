rule TTP_XOR_WriteProcessMemory_c695 {
  strings:
    $key_c695 = { 91 e7 [2] a3 c5 [2] a5 f0 [2] 8b f0 [2] b4 ec }

  condition:
    any of them
}