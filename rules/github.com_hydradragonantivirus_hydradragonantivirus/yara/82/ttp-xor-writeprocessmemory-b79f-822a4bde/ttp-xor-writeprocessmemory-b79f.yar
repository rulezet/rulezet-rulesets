rule TTP_XOR_WriteProcessMemory_b79f {
  strings:
    $key_b79f = { e0 ed [2] d2 cf [2] d4 fa [2] fa fa [2] c5 e6 }

  condition:
    any of them
}