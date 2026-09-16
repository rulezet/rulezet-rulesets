rule TTP_XOR_WriteProcessMemory_d79f {
  strings:
    $key_d79f = { 80 ed [2] b2 cf [2] b4 fa [2] 9a fa [2] a5 e6 }

  condition:
    any of them
}