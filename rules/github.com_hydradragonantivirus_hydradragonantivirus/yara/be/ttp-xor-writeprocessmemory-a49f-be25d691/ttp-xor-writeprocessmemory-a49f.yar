rule TTP_XOR_WriteProcessMemory_a49f {
  strings:
    $key_a49f = { f3 ed [2] c1 cf [2] c7 fa [2] e9 fa [2] d6 e6 }

  condition:
    any of them
}