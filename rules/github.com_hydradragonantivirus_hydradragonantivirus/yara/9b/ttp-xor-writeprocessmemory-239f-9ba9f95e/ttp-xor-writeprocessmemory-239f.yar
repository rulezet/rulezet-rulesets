rule TTP_XOR_WriteProcessMemory_239f {
  strings:
    $key_239f = { 74 ed [2] 46 cf [2] 40 fa [2] 6e fa [2] 51 e6 }

  condition:
    any of them
}