rule TTP_XOR_WriteProcessMemory_64cb {
  strings:
    $key_64cb = { 33 b9 [2] 01 9b [2] 07 ae [2] 29 ae [2] 16 b2 }

  condition:
    any of them
}