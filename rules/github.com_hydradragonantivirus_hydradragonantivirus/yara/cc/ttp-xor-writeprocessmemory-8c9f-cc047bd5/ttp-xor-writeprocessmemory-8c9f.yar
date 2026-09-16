rule TTP_XOR_WriteProcessMemory_8c9f {
  strings:
    $key_8c9f = { db ed [2] e9 cf [2] ef fa [2] c1 fa [2] fe e6 }

  condition:
    any of them
}