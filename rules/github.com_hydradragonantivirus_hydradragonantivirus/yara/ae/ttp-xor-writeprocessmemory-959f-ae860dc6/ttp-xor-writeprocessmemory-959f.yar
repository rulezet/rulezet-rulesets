rule TTP_XOR_WriteProcessMemory_959f {
  strings:
    $key_959f = { c2 ed [2] f0 cf [2] f6 fa [2] d8 fa [2] e7 e6 }

  condition:
    any of them
}