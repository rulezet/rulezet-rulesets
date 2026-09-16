rule TTP_XOR_WriteProcessMemory_3daa {
  strings:
    $key_3daa = { 6a d8 [2] 58 fa [2] 5e cf [2] 70 cf [2] 4f d3 }

  condition:
    any of them
}