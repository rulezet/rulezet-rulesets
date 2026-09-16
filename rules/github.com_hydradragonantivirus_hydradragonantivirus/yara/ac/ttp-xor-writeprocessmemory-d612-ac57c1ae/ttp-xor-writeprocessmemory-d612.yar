rule TTP_XOR_WriteProcessMemory_d612 {
  strings:
    $key_d612 = { 81 60 [2] b3 42 [2] b5 77 [2] 9b 77 [2] a4 6b }

  condition:
    any of them
}