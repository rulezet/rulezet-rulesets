rule TTP_XOR_WriteProcessMemory_ea95 {
  strings:
    $key_ea95 = { bd e7 [2] 8f c5 [2] 89 f0 [2] a7 f0 [2] 98 ec }

  condition:
    any of them
}