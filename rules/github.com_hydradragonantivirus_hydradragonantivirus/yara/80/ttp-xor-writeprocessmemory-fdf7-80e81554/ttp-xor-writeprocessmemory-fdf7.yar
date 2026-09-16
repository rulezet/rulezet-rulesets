rule TTP_XOR_WriteProcessMemory_fdf7 {
  strings:
    $key_fdf7 = { aa 85 [2] 98 a7 [2] 9e 92 [2] b0 92 [2] 8f 8e }

  condition:
    any of them
}