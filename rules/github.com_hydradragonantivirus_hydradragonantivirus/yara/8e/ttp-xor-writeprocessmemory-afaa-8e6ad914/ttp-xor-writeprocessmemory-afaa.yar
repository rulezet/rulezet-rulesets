rule TTP_XOR_WriteProcessMemory_afaa {
  strings:
    $key_afaa = { f8 d8 [2] ca fa [2] cc cf [2] e2 cf [2] dd d3 }

  condition:
    any of them
}