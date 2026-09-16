rule TTP_XOR_WriteProcessMemory_88aa {
  strings:
    $key_88aa = { df d8 [2] ed fa [2] eb cf [2] c5 cf [2] fa d3 }

  condition:
    any of them
}