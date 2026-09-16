rule TTP_XOR_WriteProcessMemory_90cb {
  strings:
    $key_90cb = { c7 b9 [2] f5 9b [2] f3 ae [2] dd ae [2] e2 b2 }

  condition:
    any of them
}