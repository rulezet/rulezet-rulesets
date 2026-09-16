rule TTP_XOR_WriteProcessMemory_ff8c {
  strings:
    $key_ff8c = { a8 fe [2] 9a dc [2] 9c e9 [2] b2 e9 [2] 8d f5 }

  condition:
    any of them
}