rule TTP_XOR_WriteProcessMemory_2fbd {
  strings:
    $key_2fbd = { 78 cf [2] 4a ed [2] 4c d8 [2] 62 d8 [2] 5d c4 }

  condition:
    any of them
}