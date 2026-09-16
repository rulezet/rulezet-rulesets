rule TTP_XOR_WriteProcessMemory_b0bd {
  strings:
    $key_b0bd = { e7 cf [2] d5 ed [2] d3 d8 [2] fd d8 [2] c2 c4 }

  condition:
    any of them
}