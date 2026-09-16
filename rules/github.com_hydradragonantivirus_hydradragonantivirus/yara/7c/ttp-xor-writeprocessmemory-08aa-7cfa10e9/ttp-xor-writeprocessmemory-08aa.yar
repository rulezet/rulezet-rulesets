rule TTP_XOR_WriteProcessMemory_08aa {
  strings:
    $key_08aa = { 5f d8 [2] 6d fa [2] 6b cf [2] 45 cf [2] 7a d3 }

  condition:
    any of them
}