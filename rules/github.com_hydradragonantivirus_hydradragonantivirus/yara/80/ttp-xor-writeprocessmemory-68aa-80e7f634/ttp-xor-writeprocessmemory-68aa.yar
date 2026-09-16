rule TTP_XOR_WriteProcessMemory_68aa {
  strings:
    $key_68aa = { 3f d8 [2] 0d fa [2] 0b cf [2] 25 cf [2] 1a d3 }

  condition:
    any of them
}