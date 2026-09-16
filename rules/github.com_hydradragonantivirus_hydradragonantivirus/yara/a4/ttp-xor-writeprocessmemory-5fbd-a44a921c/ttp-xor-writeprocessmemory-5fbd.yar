rule TTP_XOR_WriteProcessMemory_5fbd {
  strings:
    $key_5fbd = { 08 cf [2] 3a ed [2] 3c d8 [2] 12 d8 [2] 2d c4 }

  condition:
    any of them
}