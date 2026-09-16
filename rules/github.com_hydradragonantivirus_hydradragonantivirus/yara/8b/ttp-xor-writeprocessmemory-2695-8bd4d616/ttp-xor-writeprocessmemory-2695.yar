rule TTP_XOR_WriteProcessMemory_2695 {
  strings:
    $key_2695 = { 71 e7 [2] 43 c5 [2] 45 f0 [2] 6b f0 [2] 54 ec }

  condition:
    any of them
}