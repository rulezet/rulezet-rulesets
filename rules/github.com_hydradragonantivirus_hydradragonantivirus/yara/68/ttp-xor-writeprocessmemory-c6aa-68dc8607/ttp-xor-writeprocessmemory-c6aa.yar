rule TTP_XOR_WriteProcessMemory_c6aa {
  strings:
    $key_c6aa = { 91 d8 [2] a3 fa [2] a5 cf [2] 8b cf [2] b4 d3 }

  condition:
    any of them
}