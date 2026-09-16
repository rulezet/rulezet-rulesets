rule TTP_XOR_WriteProcessMemory_c8aa {
  strings:
    $key_c8aa = { 9f d8 [2] ad fa [2] ab cf [2] 85 cf [2] ba d3 }

  condition:
    any of them
}