rule TTP_XOR_WriteProcessMemory_fdf5 {
  strings:
    $key_fdf5 = { aa 87 [2] 98 a5 [2] 9e 90 [2] b0 90 [2] 8f 8c }

  condition:
    any of them
}