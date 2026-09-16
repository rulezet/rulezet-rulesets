rule TTP_XOR_WriteProcessMemory_9eaa {
  strings:
    $key_9eaa = { c9 d8 [2] fb fa [2] fd cf [2] d3 cf [2] ec d3 }

  condition:
    any of them
}