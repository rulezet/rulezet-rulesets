rule TTP_XOR_WriteProcessMemory_fdf1 {
  strings:
    $key_fdf1 = { aa 83 [2] 98 a1 [2] 9e 94 [2] b0 94 [2] 8f 88 }

  condition:
    any of them
}