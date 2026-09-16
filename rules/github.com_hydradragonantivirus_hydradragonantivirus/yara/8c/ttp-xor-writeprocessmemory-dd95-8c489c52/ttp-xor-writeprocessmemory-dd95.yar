rule TTP_XOR_WriteProcessMemory_dd95 {
  strings:
    $key_dd95 = { 8a e7 [2] b8 c5 [2] be f0 [2] 90 f0 [2] af ec }

  condition:
    any of them
}