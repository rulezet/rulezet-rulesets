rule TTP_XOR_WriteProcessMemory_a9aa {
  strings:
    $key_a9aa = { fe d8 [2] cc fa [2] ca cf [2] e4 cf [2] db d3 }

  condition:
    any of them
}