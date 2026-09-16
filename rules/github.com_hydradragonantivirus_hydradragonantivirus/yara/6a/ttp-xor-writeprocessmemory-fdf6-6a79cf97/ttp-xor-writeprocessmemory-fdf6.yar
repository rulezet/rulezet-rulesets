rule TTP_XOR_WriteProcessMemory_fdf6 {
  strings:
    $key_fdf6 = { aa 84 [2] 98 a6 [2] 9e 93 [2] b0 93 [2] 8f 8f }

  condition:
    any of them
}