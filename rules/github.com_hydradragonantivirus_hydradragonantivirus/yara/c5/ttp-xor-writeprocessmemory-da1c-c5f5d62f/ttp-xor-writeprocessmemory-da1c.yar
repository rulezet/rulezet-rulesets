rule TTP_XOR_WriteProcessMemory_da1c {
  strings:
    $key_da1c = { 8d 6e [2] bf 4c [2] b9 79 [2] 97 79 [2] a8 65 }

  condition:
    any of them
}