rule TTP_XOR_WriteProcessMemory_9a9f {
  strings:
    $key_9a9f = { cd ed [2] ff cf [2] f9 fa [2] d7 fa [2] e8 e6 }

  condition:
    any of them
}