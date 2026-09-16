rule TTP_XOR_WriteProcessMemory_1db5 {
  strings:
    $key_1db5 = { 4a c7 [2] 78 e5 [2] 7e d0 [2] 50 d0 [2] 6f cc }

  condition:
    any of them
}