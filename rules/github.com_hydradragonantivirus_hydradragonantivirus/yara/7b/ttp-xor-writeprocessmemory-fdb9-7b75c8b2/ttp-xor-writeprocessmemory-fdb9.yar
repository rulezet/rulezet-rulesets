rule TTP_XOR_WriteProcessMemory_fdb9 {
  strings:
    $key_fdb9 = { aa cb [2] 98 e9 [2] 9e dc [2] b0 dc [2] 8f c0 }

  condition:
    any of them
}