rule TTP_XOR_WriteProcessMemory_afbd {
  strings:
    $key_afbd = { f8 cf [2] ca ed [2] cc d8 [2] e2 d8 [2] dd c4 }

  condition:
    any of them
}