rule TTP_XOR_WriteProcessMemory_259f {
  strings:
    $key_259f = { 72 ed [2] 40 cf [2] 46 fa [2] 68 fa [2] 57 e6 }

  condition:
    any of them
}