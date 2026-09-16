rule TTP_XOR_WriteProcessMemory_d29f {
  strings:
    $key_d29f = { 85 ed [2] b7 cf [2] b1 fa [2] 9f fa [2] a0 e6 }

  condition:
    any of them
}