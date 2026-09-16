rule TTP_XOR_WriteProcessMemory_40bd {
  strings:
    $key_40bd = { 17 cf [2] 25 ed [2] 23 d8 [2] 0d d8 [2] 32 c4 }

  condition:
    any of them
}