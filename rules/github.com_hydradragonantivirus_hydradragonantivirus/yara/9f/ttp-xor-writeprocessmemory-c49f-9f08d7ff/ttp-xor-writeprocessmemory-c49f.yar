rule TTP_XOR_WriteProcessMemory_c49f {
  strings:
    $key_c49f = { 93 ed [2] a1 cf [2] a7 fa [2] 89 fa [2] b6 e6 }

  condition:
    any of them
}