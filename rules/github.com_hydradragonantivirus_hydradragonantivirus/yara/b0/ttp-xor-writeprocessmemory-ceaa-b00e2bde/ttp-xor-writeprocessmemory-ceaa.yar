rule TTP_XOR_WriteProcessMemory_ceaa {
  strings:
    $key_ceaa = { 99 d8 [2] ab fa [2] ad cf [2] 83 cf [2] bc d3 }

  condition:
    any of them
}