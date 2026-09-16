rule TTP_XOR_WriteProcessMemory_9abd {
  strings:
    $key_9abd = { cd cf [2] ff ed [2] f9 d8 [2] d7 d8 [2] e8 c4 }

  condition:
    any of them
}