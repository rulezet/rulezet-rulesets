rule TTP_XOR_WriteProcessMemory_95bd {
  strings:
    $key_95bd = { c2 cf [2] f0 ed [2] f6 d8 [2] d8 d8 [2] e7 c4 }

  condition:
    any of them
}