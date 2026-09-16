rule TTP_XOR_WriteProcessMemory_da1b {
  strings:
    $key_da1b = { 8d 69 [2] bf 4b [2] b9 7e [2] 97 7e [2] a8 62 }

  condition:
    any of them
}