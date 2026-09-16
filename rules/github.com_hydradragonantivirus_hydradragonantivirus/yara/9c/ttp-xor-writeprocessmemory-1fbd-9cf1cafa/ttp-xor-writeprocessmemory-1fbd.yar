rule TTP_XOR_WriteProcessMemory_1fbd {
  strings:
    $key_1fbd = { 48 cf [2] 7a ed [2] 7c d8 [2] 52 d8 [2] 6d c4 }

  condition:
    any of them
}