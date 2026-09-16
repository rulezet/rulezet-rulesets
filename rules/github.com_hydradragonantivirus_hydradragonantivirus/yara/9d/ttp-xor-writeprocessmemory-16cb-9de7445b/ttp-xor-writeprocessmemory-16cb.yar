rule TTP_XOR_WriteProcessMemory_16cb {
  strings:
    $key_16cb = { 41 b9 [2] 73 9b [2] 75 ae [2] 5b ae [2] 64 b2 }

  condition:
    any of them
}