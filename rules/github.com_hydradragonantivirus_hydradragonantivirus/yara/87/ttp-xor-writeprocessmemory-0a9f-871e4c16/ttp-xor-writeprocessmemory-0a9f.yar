rule TTP_XOR_WriteProcessMemory_0a9f {
  strings:
    $key_0a9f = { 5d ed [2] 6f cf [2] 69 fa [2] 47 fa [2] 78 e6 }

  condition:
    any of them
}