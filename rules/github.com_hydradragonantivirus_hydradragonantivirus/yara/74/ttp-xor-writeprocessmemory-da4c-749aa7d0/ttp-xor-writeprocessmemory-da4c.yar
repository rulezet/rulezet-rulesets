rule TTP_XOR_WriteProcessMemory_da4c {
  strings:
    $key_da4c = { 8d 3e [2] bf 1c [2] b9 29 [2] 97 29 [2] a8 35 }

  condition:
    any of them
}