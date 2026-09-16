rule TTP_XOR_WriteProcessMemory_3d9f {
  strings:
    $key_3d9f = { 6a ed [2] 58 cf [2] 5e fa [2] 70 fa [2] 4f e6 }

  condition:
    any of them
}