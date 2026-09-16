rule TTP_XOR_WriteProcessMemory_1d9f {
  strings:
    $key_1d9f = { 4a ed [2] 78 cf [2] 7e fa [2] 50 fa [2] 6f e6 }

  condition:
    any of them
}