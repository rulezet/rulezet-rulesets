rule TTP_XOR_WriteProcessMemory_dcaa {
  strings:
    $key_dcaa = { 8b d8 [2] b9 fa [2] bf cf [2] 91 cf [2] ae d3 }

  condition:
    any of them
}