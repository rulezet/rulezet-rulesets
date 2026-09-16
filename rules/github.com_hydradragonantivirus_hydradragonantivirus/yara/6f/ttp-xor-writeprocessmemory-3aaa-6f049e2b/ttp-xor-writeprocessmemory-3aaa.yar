rule TTP_XOR_WriteProcessMemory_3aaa {
  strings:
    $key_3aaa = { 6d d8 [2] 5f fa [2] 59 cf [2] 77 cf [2] 48 d3 }

  condition:
    any of them
}