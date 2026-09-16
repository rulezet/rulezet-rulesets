rule TTP_XOR_WriteProcessMemory_2a9f {
  strings:
    $key_2a9f = { 7d ed [2] 4f cf [2] 49 fa [2] 67 fa [2] 58 e6 }

  condition:
    any of them
}