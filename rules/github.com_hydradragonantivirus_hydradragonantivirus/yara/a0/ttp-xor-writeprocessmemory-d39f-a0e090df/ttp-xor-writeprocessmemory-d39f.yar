rule TTP_XOR_WriteProcessMemory_d39f {
  strings:
    $key_d39f = { 84 ed [2] b6 cf [2] b0 fa [2] 9e fa [2] a1 e6 }

  condition:
    any of them
}