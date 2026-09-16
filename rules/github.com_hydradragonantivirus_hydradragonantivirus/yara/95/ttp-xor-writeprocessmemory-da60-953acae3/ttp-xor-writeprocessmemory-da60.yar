rule TTP_XOR_WriteProcessMemory_da60 {
  strings:
    $key_da60 = { 8d 12 [2] bf 30 [2] b9 05 [2] 97 05 [2] a8 19 }

  condition:
    any of them
}