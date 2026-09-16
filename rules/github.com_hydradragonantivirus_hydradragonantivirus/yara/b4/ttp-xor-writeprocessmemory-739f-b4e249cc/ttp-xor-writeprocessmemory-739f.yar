rule TTP_XOR_WriteProcessMemory_739f {
  strings:
    $key_739f = { 24 ed [2] 16 cf [2] 10 fa [2] 3e fa [2] 01 e6 }

  condition:
    any of them
}