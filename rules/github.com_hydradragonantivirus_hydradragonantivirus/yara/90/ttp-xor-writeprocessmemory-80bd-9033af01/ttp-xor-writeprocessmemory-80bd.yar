rule TTP_XOR_WriteProcessMemory_80bd {
  strings:
    $key_80bd = { d7 cf [2] e5 ed [2] e3 d8 [2] cd d8 [2] f2 c4 }

  condition:
    any of them
}