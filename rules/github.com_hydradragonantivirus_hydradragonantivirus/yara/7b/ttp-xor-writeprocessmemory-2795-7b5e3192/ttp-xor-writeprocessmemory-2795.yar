rule TTP_XOR_WriteProcessMemory_2795 {
  strings:
    $key_2795 = { 70 e7 [2] 42 c5 [2] 44 f0 [2] 6a f0 [2] 55 ec }

  condition:
    any of them
}