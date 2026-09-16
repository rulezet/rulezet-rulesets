rule TTP_XOR_WriteProcessMemory_da2e {
  strings:
    $key_da2e = { 8d 5c [2] bf 7e [2] b9 4b [2] 97 4b [2] a8 57 }

  condition:
    any of them
}