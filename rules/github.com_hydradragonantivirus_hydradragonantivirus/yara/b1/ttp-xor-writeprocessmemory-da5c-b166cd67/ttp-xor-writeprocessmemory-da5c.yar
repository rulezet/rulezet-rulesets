rule TTP_XOR_WriteProcessMemory_da5c {
  strings:
    $key_da5c = { 8d 2e [2] bf 0c [2] b9 39 [2] 97 39 [2] a8 25 }

  condition:
    any of them
}