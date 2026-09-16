rule TTP_XOR_WriteProcessMemory_80aa {
  strings:
    $key_80aa = { d7 d8 [2] e5 fa [2] e3 cf [2] cd cf [2] f2 d3 }

  condition:
    any of them
}