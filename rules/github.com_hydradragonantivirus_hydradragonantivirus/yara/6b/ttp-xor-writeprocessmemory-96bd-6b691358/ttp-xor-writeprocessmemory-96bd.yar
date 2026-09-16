rule TTP_XOR_WriteProcessMemory_96bd {
  strings:
    $key_96bd = { c1 cf [2] f3 ed [2] f5 d8 [2] db d8 [2] e4 c4 }

  condition:
    any of them
}