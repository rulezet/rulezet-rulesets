rule TTP_XOR_WriteProcessMemory_fdf8 {
  strings:
    $key_fdf8 = { aa 8a [2] 98 a8 [2] 9e 9d [2] b0 9d [2] 8f 81 }

  condition:
    any of them
}