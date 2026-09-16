rule TTP_XOR_WriteProcessMemory_249f {
  strings:
    $key_249f = { 73 ed [2] 41 cf [2] 47 fa [2] 69 fa [2] 56 e6 }

  condition:
    any of them
}