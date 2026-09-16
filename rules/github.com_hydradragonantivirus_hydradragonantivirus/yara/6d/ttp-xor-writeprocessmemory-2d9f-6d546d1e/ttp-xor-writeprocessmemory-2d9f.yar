rule TTP_XOR_WriteProcessMemory_2d9f {
  strings:
    $key_2d9f = { 7a ed [2] 48 cf [2] 4e fa [2] 60 fa [2] 5f e6 }

  condition:
    any of them
}