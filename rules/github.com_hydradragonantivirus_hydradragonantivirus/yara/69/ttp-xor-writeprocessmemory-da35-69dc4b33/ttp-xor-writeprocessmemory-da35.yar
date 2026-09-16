rule TTP_XOR_WriteProcessMemory_da35 {
  strings:
    $key_da35 = { 8d 47 [2] bf 65 [2] b9 50 [2] 97 50 [2] a8 4c }

  condition:
    any of them
}