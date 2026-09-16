rule TTP_XOR_WriteProcessMemory_52aa {
  strings:
    $key_52aa = { 05 d8 [2] 37 fa [2] 31 cf [2] 1f cf [2] 20 d3 }

  condition:
    any of them
}