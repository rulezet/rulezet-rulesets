rule TTP_XOR_WriteProcessMemory_3fbd {
  strings:
    $key_3fbd = { 68 cf [2] 5a ed [2] 5c d8 [2] 72 d8 [2] 4d c4 }

  condition:
    any of them
}