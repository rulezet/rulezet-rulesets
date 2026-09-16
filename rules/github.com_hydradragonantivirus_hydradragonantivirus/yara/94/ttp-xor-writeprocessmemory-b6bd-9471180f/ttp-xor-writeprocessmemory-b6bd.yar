rule TTP_XOR_WriteProcessMemory_b6bd {
  strings:
    $key_b6bd = { e1 cf [2] d3 ed [2] d5 d8 [2] fb d8 [2] c4 c4 }

  condition:
    any of them
}