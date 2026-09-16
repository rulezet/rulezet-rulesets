rule TTP_XOR_WriteProcessMemory_da00 {
  strings:
    $key_da00 = { 8d 72 [2] bf 50 [2] b9 65 [2] 97 65 [2] a8 79 }

  condition:
    any of them
}