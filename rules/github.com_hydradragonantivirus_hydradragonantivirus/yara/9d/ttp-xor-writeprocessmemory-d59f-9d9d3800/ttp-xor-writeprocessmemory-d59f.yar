rule TTP_XOR_WriteProcessMemory_d59f {
  strings:
    $key_d59f = { 82 ed [2] b0 cf [2] b6 fa [2] 98 fa [2] a7 e6 }

  condition:
    any of them
}