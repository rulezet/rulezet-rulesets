rule TTP_XOR_WriteProcessMemory_f495 {
  strings:
    $key_f495 = { a3 e7 [2] 91 c5 [2] 97 f0 [2] b9 f0 [2] 86 ec }

  condition:
    any of them
}