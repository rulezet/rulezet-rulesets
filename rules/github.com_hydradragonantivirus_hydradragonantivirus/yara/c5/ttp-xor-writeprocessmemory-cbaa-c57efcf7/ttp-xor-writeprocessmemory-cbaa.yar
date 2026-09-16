rule TTP_XOR_WriteProcessMemory_cbaa {
  strings:
    $key_cbaa = { 9c d8 [2] ae fa [2] a8 cf [2] 86 cf [2] b9 d3 }

  condition:
    any of them
}