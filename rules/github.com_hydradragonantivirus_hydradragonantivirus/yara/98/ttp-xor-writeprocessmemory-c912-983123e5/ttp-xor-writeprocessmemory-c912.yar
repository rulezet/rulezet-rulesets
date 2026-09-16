rule TTP_XOR_WriteProcessMemory_c912 {
  strings:
    $key_c912 = { 9e 60 [2] ac 42 [2] aa 77 [2] 84 77 [2] bb 6b }

  condition:
    any of them
}