rule TTP_XOR_WriteProcessMemory_efbd {
  strings:
    $key_efbd = { b8 cf [2] 8a ed [2] 8c d8 [2] a2 d8 [2] 9d c4 }

  condition:
    any of them
}