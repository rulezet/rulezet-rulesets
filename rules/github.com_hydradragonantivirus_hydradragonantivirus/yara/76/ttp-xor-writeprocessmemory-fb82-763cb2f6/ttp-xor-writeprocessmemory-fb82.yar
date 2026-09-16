rule TTP_XOR_WriteProcessMemory_fb82 {
  strings:
    $key_fb82 = { ac f0 [2] 9e d2 [2] 98 e7 [2] b6 e7 [2] 89 fb }

  condition:
    any of them
}