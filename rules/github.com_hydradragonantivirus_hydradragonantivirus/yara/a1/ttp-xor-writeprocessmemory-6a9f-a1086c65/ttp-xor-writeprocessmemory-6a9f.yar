rule TTP_XOR_WriteProcessMemory_6a9f {
  strings:
    $key_6a9f = { 3d ed [2] 0f cf [2] 09 fa [2] 27 fa [2] 18 e6 }

  condition:
    any of them
}