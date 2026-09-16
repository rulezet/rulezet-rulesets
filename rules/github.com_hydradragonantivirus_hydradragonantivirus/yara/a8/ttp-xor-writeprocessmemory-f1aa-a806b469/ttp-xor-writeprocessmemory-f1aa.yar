rule TTP_XOR_WriteProcessMemory_f1aa {
  strings:
    $key_f1aa = { a6 d8 [2] 94 fa [2] 92 cf [2] bc cf [2] 83 d3 }

  condition:
    any of them
}