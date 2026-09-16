rule TTP_XOR_WriteProcessMemory_da1e {
  strings:
    $key_da1e = { 8d 6c [2] bf 4e [2] b9 7b [2] 97 7b [2] a8 67 }

  condition:
    any of them
}