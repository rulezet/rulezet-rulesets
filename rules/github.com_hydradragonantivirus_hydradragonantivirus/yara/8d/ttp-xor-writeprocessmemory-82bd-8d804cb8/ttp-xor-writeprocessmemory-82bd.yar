rule TTP_XOR_WriteProcessMemory_82bd {
  strings:
    $key_82bd = { d5 cf [2] e7 ed [2] e1 d8 [2] cf d8 [2] f0 c4 }

  condition:
    any of them
}