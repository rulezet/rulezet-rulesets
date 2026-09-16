rule TTP_XOR_WriteProcessMemory_d627 {
  strings:
    $key_d627 = { 81 55 [2] b3 77 [2] b5 42 [2] 9b 42 [2] a4 5e }

  condition:
    any of them
}