rule TTP_XOR_WriteProcessMemory_c205 {
  strings:
    $key_c205 = { 95 77 [2] a7 55 [2] a1 60 [2] 8f 60 [2] b0 7c }

  condition:
    any of them
}