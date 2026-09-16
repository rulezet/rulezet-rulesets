rule TTP_XOR_WriteProcessMemory_fdf4 {
  strings:
    $key_fdf4 = { aa 86 [2] 98 a4 [2] 9e 91 [2] b0 91 [2] 8f 8d }

  condition:
    any of them
}