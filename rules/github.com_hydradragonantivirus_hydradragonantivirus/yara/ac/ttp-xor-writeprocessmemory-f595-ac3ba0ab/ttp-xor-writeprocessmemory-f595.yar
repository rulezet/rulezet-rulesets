rule TTP_XOR_WriteProcessMemory_f595 {
  strings:
    $key_f595 = { a2 e7 [2] 90 c5 [2] 96 f0 [2] b8 f0 [2] 87 ec }

  condition:
    any of them
}