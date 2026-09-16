rule TTP_XOR_WriteProcessMemory_c527 {
  strings:
    $key_c527 = { 92 55 [2] a0 77 [2] a6 42 [2] 88 42 [2] b7 5e }

  condition:
    any of them
}