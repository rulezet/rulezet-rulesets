rule TTP_XOR_WriteProcessMemory_d6bd {
  strings:
    $key_d6bd = { 81 cf [2] b3 ed [2] b5 d8 [2] 9b d8 [2] a4 c4 }

  condition:
    any of them
}