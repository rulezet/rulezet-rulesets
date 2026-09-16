rule TTP_XOR_WriteProcessMemory_b295 {
  strings:
    $key_b295 = { e5 e7 [2] d7 c5 [2] d1 f0 [2] ff f0 [2] c0 ec }

  condition:
    any of them
}