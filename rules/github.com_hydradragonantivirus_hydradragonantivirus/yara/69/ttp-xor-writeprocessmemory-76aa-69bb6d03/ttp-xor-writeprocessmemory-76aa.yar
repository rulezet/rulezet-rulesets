rule TTP_XOR_WriteProcessMemory_76aa {
  strings:
    $key_76aa = { 21 d8 [2] 13 fa [2] 15 cf [2] 3b cf [2] 04 d3 }

  condition:
    any of them
}