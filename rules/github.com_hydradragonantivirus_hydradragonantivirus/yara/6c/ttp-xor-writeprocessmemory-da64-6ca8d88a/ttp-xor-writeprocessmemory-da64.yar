rule TTP_XOR_WriteProcessMemory_da64 {
  strings:
    $key_da64 = { 8d 16 [2] bf 34 [2] b9 01 [2] 97 01 [2] a8 1d }

  condition:
    any of them
}