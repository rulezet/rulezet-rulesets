rule TTP_XOR_WriteProcessMemory_f6cb {
  strings:
    $key_f6cb = { a1 b9 [2] 93 9b [2] 95 ae [2] bb ae [2] 84 b2 }

  condition:
    any of them
}