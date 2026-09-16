rule TTP_XOR_WriteProcessMemory_97bd {
  strings:
    $key_97bd = { c0 cf [2] f2 ed [2] f4 d8 [2] da d8 [2] e5 c4 }

  condition:
    any of them
}