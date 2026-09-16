rule TTP_XOR_WriteProcessMemory_2db5 {
  strings:
    $key_2db5 = { 7a c7 [2] 48 e5 [2] 4e d0 [2] 60 d0 [2] 5f cc }

  condition:
    any of them
}