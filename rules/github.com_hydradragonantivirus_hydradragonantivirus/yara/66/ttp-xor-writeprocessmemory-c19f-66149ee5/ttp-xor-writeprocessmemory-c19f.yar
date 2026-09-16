rule TTP_XOR_WriteProcessMemory_c19f {
  strings:
    $key_c19f = { 96 ed [2] a4 cf [2] a2 fa [2] 8c fa [2] b3 e6 }

  condition:
    any of them
}