rule TTP_XOR_WriteProcessMemory_70aa {
  strings:
    $key_70aa = { 27 d8 [2] 15 fa [2] 13 cf [2] 3d cf [2] 02 d3 }

  condition:
    any of them
}