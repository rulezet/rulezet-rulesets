rule TTP_XOR_WriteProcessMemory_da57 {
  strings:
    $key_da57 = { 8d 25 [2] bf 07 [2] b9 32 [2] 97 32 [2] a8 2e }

  condition:
    any of them
}