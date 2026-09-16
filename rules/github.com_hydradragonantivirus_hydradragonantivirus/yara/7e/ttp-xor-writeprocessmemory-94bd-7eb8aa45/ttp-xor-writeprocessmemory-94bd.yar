rule TTP_XOR_WriteProcessMemory_94bd {
  strings:
    $key_94bd = { c3 cf [2] f1 ed [2] f7 d8 [2] d9 d8 [2] e6 c4 }

  condition:
    any of them
}