rule TTP_XOR_WriteProcessMemory_a3bd {
  strings:
    $key_a3bd = { f4 cf [2] c6 ed [2] c0 d8 [2] ee d8 [2] d1 c4 }

  condition:
    any of them
}