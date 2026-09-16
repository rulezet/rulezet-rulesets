rule TTP_XOR_WriteProcessMemory_e3aa {
  strings:
    $key_e3aa = { b4 d8 [2] 86 fa [2] 80 cf [2] ae cf [2] 91 d3 }

  condition:
    any of them
}