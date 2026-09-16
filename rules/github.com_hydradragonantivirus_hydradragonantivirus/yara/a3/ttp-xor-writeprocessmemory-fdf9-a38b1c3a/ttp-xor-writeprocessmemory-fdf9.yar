rule TTP_XOR_WriteProcessMemory_fdf9 {
  strings:
    $key_fdf9 = { aa 8b [2] 98 a9 [2] 9e 9c [2] b0 9c [2] 8f 80 }

  condition:
    any of them
}