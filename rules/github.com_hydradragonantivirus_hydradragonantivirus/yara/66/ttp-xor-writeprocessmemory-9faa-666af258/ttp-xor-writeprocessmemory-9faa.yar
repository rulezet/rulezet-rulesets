rule TTP_XOR_WriteProcessMemory_9faa {
  strings:
    $key_9faa = { c8 d8 [2] fa fa [2] fc cf [2] d2 cf [2] ed d3 }

  condition:
    any of them
}