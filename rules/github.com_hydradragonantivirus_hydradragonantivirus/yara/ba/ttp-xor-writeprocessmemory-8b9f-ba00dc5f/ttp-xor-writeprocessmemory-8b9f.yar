rule TTP_XOR_WriteProcessMemory_8b9f {
  strings:
    $key_8b9f = { dc ed [2] ee cf [2] e8 fa [2] c6 fa [2] f9 e6 }

  condition:
    any of them
}