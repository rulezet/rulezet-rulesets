rule TTP_XOR_WriteProcessMemory_e705 {
  strings:
    $key_e705 = { b0 77 [2] 82 55 [2] 84 60 [2] aa 60 [2] 95 7c }

  condition:
    any of them
}