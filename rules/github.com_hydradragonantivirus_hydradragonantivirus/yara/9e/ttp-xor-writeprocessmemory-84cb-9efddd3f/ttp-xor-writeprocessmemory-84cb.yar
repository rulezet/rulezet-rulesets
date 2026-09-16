rule TTP_XOR_WriteProcessMemory_84cb {
  strings:
    $key_84cb = { d3 b9 [2] e1 9b [2] e7 ae [2] c9 ae [2] f6 b2 }

  condition:
    any of them
}