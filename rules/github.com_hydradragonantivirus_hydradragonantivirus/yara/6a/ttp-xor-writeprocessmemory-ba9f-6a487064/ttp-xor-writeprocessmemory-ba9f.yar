rule TTP_XOR_WriteProcessMemory_ba9f {
  strings:
    $key_ba9f = { ed ed [2] df cf [2] d9 fa [2] f7 fa [2] c8 e6 }

  condition:
    any of them
}