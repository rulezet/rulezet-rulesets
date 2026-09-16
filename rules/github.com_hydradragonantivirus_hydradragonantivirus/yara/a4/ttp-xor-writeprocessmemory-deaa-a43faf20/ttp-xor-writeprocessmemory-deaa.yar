rule TTP_XOR_WriteProcessMemory_deaa {
  strings:
    $key_deaa = { 89 d8 [2] bb fa [2] bd cf [2] 93 cf [2] ac d3 }

  condition:
    any of them
}