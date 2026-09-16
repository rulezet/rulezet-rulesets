rule TTP_XOR_WriteProcessMemory_a69f {
  strings:
    $key_a69f = { f1 ed [2] c3 cf [2] c5 fa [2] eb fa [2] d4 e6 }

  condition:
    any of them
}