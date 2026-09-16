rule TTP_XOR_WriteProcessMemory_92bd {
  strings:
    $key_92bd = { c5 cf [2] f7 ed [2] f1 d8 [2] df d8 [2] e0 c4 }

  condition:
    any of them
}