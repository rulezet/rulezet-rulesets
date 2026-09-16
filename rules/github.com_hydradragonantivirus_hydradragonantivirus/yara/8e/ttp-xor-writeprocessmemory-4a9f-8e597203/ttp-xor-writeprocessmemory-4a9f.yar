rule TTP_XOR_WriteProcessMemory_4a9f {
  strings:
    $key_4a9f = { 1d ed [2] 2f cf [2] 29 fa [2] 07 fa [2] 38 e6 }

  condition:
    any of them
}