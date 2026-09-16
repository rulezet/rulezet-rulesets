rule TTP_XOR_WriteProcessMemory_ec9f {
  strings:
    $key_ec9f = { bb ed [2] 89 cf [2] 8f fa [2] a1 fa [2] 9e e6 }

  condition:
    any of them
}