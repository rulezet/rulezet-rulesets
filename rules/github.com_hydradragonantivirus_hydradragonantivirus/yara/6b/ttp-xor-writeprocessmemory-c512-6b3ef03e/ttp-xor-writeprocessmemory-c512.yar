rule TTP_XOR_WriteProcessMemory_c512 {
  strings:
    $key_c512 = { 92 60 [2] a0 42 [2] a6 77 [2] 88 77 [2] b7 6b }

  condition:
    any of them
}