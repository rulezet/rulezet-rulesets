rule TTP_XOR_WriteProcessMemory_a09f {
  strings:
    $key_a09f = { f7 ed [2] c5 cf [2] c3 fa [2] ed fa [2] d2 e6 }

  condition:
    any of them
}