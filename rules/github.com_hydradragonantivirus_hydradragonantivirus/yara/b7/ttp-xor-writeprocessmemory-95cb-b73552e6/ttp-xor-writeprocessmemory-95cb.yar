rule TTP_XOR_WriteProcessMemory_95cb {
  strings:
    $key_95cb = { c2 b9 [2] f0 9b [2] f6 ae [2] d8 ae [2] e7 b2 }

  condition:
    any of them
}