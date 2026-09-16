rule TTP_XOR_WriteProcessMemory_80cb {
  strings:
    $key_80cb = { d7 b9 [2] e5 9b [2] e3 ae [2] cd ae [2] f2 b2 }

  condition:
    any of them
}