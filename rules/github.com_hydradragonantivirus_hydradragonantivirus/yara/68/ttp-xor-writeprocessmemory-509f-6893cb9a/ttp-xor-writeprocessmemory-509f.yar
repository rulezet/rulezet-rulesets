rule TTP_XOR_WriteProcessMemory_509f {
  strings:
    $key_509f = { 07 ed [2] 35 cf [2] 33 fa [2] 1d fa [2] 22 e6 }

  condition:
    any of them
}