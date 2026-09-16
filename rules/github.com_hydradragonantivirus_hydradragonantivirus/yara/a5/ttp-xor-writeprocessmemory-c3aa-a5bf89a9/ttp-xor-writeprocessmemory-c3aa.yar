rule TTP_XOR_WriteProcessMemory_c3aa {
  strings:
    $key_c3aa = { 94 d8 [2] a6 fa [2] a0 cf [2] 8e cf [2] b1 d3 }

  condition:
    any of them
}