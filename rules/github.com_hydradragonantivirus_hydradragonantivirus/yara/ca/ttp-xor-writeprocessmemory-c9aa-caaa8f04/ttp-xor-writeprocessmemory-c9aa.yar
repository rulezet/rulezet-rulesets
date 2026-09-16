rule TTP_XOR_WriteProcessMemory_c9aa {
  strings:
    $key_c9aa = { 9e d8 [2] ac fa [2] aa cf [2] 84 cf [2] bb d3 }

  condition:
    any of them
}