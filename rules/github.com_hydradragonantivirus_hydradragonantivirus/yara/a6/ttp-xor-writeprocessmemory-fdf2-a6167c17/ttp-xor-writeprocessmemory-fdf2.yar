rule TTP_XOR_WriteProcessMemory_fdf2 {
  strings:
    $key_fdf2 = { aa 80 [2] 98 a2 [2] 9e 97 [2] b0 97 [2] 8f 8b }

  condition:
    any of them
}