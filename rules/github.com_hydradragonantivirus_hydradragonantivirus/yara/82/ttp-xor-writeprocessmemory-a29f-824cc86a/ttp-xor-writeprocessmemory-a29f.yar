rule TTP_XOR_WriteProcessMemory_a29f {
  strings:
    $key_a29f = { f5 ed [2] c7 cf [2] c1 fa [2] ef fa [2] d0 e6 }

  condition:
    any of them
}