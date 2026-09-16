rule TTP_XOR_WriteProcessMemory_89aa {
  strings:
    $key_89aa = { de d8 [2] ec fa [2] ea cf [2] c4 cf [2] fb d3 }

  condition:
    any of them
}