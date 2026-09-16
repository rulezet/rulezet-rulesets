rule TTP_XOR_WriteProcessMemory_83cb {
  strings:
    $key_83cb = { d4 b9 [2] e6 9b [2] e0 ae [2] ce ae [2] f1 b2 }

  condition:
    any of them
}