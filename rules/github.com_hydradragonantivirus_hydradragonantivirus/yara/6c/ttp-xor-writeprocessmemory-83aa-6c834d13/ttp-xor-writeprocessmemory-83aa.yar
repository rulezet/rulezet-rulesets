rule TTP_XOR_WriteProcessMemory_83aa {
  strings:
    $key_83aa = { d4 d8 [2] e6 fa [2] e0 cf [2] ce cf [2] f1 d3 }

  condition:
    any of them
}