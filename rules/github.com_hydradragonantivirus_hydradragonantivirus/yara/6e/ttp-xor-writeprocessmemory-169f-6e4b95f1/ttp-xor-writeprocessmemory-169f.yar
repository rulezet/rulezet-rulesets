rule TTP_XOR_WriteProcessMemory_169f {
  strings:
    $key_169f = { 41 ed [2] 73 cf [2] 75 fa [2] 5b fa [2] 64 e6 }

  condition:
    any of them
}