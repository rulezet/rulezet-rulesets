rule TTP_XOR_WriteProcessMemory_92a1 {
  strings:
    $key_92a1 = { c5 d3 [2] f7 f1 [2] f1 c4 [2] df c4 [2] e0 d8 }

  condition:
    any of them
}