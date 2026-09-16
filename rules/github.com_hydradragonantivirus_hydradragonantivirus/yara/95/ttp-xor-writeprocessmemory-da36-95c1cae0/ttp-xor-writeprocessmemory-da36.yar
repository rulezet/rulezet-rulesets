rule TTP_XOR_WriteProcessMemory_da36 {
  strings:
    $key_da36 = { 8d 44 [2] bf 66 [2] b9 53 [2] 97 53 [2] a8 4f }

  condition:
    any of them
}