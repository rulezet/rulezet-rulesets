rule TTP_XOR_WriteProcessMemory_d09f {
  strings:
    $key_d09f = { 87 ed [2] b5 cf [2] b3 fa [2] 9d fa [2] a2 e6 }

  condition:
    any of them
}