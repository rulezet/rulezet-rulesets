rule TTP_XOR_WriteProcessMemory_a1bd {
  strings:
    $key_a1bd = { f6 cf [2] c4 ed [2] c2 d8 [2] ec d8 [2] d3 c4 }

  condition:
    any of them
}