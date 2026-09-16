rule TTP_XOR_WriteProcessMemory_f5cb {
  strings:
    $key_f5cb = { a2 b9 [2] 90 9b [2] 96 ae [2] b8 ae [2] 87 b2 }

  condition:
    any of them
}