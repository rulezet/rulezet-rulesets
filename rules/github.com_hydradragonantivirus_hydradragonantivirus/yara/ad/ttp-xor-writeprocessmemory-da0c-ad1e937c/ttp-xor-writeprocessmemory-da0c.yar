rule TTP_XOR_WriteProcessMemory_da0c {
  strings:
    $key_da0c = { 8d 7e [2] bf 5c [2] b9 69 [2] 97 69 [2] a8 75 }

  condition:
    any of them
}