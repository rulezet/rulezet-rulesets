rule TTP_XOR_WriteProcessMemory_c5aa {
  strings:
    $key_c5aa = { 92 d8 [2] a0 fa [2] a6 cf [2] 88 cf [2] b7 d3 }

  condition:
    any of them
}