rule TTP_XOR_WriteProcessMemory_909f {
  strings:
    $key_909f = { c7 ed [2] f5 cf [2] f3 fa [2] dd fa [2] e2 e6 }

  condition:
    any of them
}