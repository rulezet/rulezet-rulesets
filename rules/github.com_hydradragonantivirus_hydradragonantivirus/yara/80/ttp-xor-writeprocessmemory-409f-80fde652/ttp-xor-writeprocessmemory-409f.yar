rule TTP_XOR_WriteProcessMemory_409f {
  strings:
    $key_409f = { 17 ed [2] 25 cf [2] 23 fa [2] 0d fa [2] 32 e6 }

  condition:
    any of them
}