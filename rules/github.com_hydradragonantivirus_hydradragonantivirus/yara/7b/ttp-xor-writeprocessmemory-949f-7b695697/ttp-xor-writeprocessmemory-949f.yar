rule TTP_XOR_WriteProcessMemory_949f {
  strings:
    $key_949f = { c3 ed [2] f1 cf [2] f7 fa [2] d9 fa [2] e6 e6 }

  condition:
    any of them
}