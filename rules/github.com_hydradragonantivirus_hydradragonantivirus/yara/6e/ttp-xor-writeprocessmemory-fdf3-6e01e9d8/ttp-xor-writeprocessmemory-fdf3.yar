rule TTP_XOR_WriteProcessMemory_fdf3 {
  strings:
    $key_fdf3 = { aa 81 [2] 98 a3 [2] 9e 96 [2] b0 96 [2] 8f 8a }

  condition:
    any of them
}