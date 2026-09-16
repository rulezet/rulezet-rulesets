rule TTP_XOR_WriteProcessMemory_489f {
  strings:
    $key_489f = { 1f ed [2] 2d cf [2] 2b fa [2] 05 fa [2] 3a e6 }

  condition:
    any of them
}