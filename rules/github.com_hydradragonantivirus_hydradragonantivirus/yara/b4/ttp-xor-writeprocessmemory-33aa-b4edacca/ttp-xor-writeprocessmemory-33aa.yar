rule TTP_XOR_WriteProcessMemory_33aa {
  strings:
    $key_33aa = { 64 d8 [2] 56 fa [2] 50 cf [2] 7e cf [2] 41 d3 }

  condition:
    any of them
}