rule TTP_XOR_WriteProcessMemory_2b80 {
  strings:
    $key_2b80 = { 7c f2 [2] 4e d0 [2] 48 e5 [2] 66 e5 [2] 59 f9 }

  condition:
    any of them
}