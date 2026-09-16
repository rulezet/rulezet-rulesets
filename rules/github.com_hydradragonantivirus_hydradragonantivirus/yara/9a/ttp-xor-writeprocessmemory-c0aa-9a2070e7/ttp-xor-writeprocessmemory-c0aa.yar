rule TTP_XOR_WriteProcessMemory_c0aa {
  strings:
    $key_c0aa = { 97 d8 [2] a5 fa [2] a3 cf [2] 8d cf [2] b2 d3 }

  condition:
    any of them
}