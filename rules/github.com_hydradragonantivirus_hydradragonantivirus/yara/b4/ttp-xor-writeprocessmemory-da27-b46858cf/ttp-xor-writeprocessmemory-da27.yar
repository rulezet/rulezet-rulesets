rule TTP_XOR_WriteProcessMemory_da27 {
  strings:
    $key_da27 = { 8d 55 [2] bf 77 [2] b9 42 [2] 97 42 [2] a8 5e }

  condition:
    any of them
}