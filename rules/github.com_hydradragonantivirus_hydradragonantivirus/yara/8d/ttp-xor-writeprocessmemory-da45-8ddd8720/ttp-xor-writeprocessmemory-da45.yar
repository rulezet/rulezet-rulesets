rule TTP_XOR_WriteProcessMemory_da45 {
  strings:
    $key_da45 = { 8d 37 [2] bf 15 [2] b9 20 [2] 97 20 [2] a8 3c }

  condition:
    any of them
}