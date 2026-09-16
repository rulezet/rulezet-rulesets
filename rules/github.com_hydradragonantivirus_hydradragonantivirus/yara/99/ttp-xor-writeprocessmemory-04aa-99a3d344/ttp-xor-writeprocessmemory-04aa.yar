rule TTP_XOR_WriteProcessMemory_04aa {
  strings:
    $key_04aa = { 53 d8 [2] 61 fa [2] 67 cf [2] 49 cf [2] 76 d3 }

  condition:
    any of them
}