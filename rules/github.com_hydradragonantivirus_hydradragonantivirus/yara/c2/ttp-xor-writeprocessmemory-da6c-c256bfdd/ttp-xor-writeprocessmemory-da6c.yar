rule TTP_XOR_WriteProcessMemory_da6c {
  strings:
    $key_da6c = { 8d 1e [2] bf 3c [2] b9 09 [2] 97 09 [2] a8 15 }

  condition:
    any of them
}