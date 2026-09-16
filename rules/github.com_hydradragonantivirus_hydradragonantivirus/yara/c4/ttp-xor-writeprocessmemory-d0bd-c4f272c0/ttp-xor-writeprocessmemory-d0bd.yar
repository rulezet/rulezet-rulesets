rule TTP_XOR_WriteProcessMemory_d0bd {
  strings:
    $key_d0bd = { 87 cf [2] b5 ed [2] b3 d8 [2] 9d d8 [2] a2 c4 }

  condition:
    any of them
}