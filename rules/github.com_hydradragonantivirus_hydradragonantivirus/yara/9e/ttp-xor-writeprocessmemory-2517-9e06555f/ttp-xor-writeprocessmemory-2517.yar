rule TTP_XOR_WriteProcessMemory_2517 {
  strings:
    $key_2517 = { 72 65 [2] 40 47 [2] 46 72 [2] 68 72 [2] 57 6e }

  condition:
    any of them
}