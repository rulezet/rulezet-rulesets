rule TTP_XOR_WriteProcessMemory_2b82 {
  strings:
    $key_2b82 = { 7c f0 [2] 4e d2 [2] 48 e7 [2] 66 e7 [2] 59 fb }

  condition:
    any of them
}