rule TTP_XOR_WriteProcessMemory_c2bd {
  strings:
    $key_c2bd = { 95 cf [2] a7 ed [2] a1 d8 [2] 8f d8 [2] b0 c4 }

  condition:
    any of them
}