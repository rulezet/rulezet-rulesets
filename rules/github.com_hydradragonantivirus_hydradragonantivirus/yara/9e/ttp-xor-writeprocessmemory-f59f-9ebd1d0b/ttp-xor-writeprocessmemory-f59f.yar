rule TTP_XOR_WriteProcessMemory_f59f {
  strings:
    $key_f59f = { a2 ed [2] 90 cf [2] 96 fa [2] b8 fa [2] 87 e6 }

  condition:
    any of them
}