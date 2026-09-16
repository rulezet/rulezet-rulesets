rule TTP_XOR_WriteProcessMemory_12bd {
  strings:
    $key_12bd = { 45 cf [2] 77 ed [2] 71 d8 [2] 5f d8 [2] 60 c4 }

  condition:
    any of them
}