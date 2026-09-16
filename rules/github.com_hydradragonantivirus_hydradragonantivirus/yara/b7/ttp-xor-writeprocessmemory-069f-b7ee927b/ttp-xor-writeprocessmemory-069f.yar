rule TTP_XOR_WriteProcessMemory_069f {
  strings:
    $key_069f = { 51 ed [2] 63 cf [2] 65 fa [2] 4b fa [2] 74 e6 }

  condition:
    any of them
}