rule TTP_XOR_WriteProcessMemory_eaaa {
  strings:
    $key_eaaa = { bd d8 [2] 8f fa [2] 89 cf [2] a7 cf [2] 98 d3 }

  condition:
    any of them
}