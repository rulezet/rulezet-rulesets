rule TTP_XOR_WriteProcessMemory_da2b {
  strings:
    $key_da2b = { 8d 59 [2] bf 7b [2] b9 4e [2] 97 4e [2] a8 52 }

  condition:
    any of them
}