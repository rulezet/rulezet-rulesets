rule TTP_XOR_WriteProcessMemory_faaa {
  strings:
    $key_faaa = { ad d8 [2] 9f fa [2] 99 cf [2] b7 cf [2] 88 d3 }

  condition:
    any of them
}