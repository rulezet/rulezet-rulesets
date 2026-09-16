rule TTP_XOR_WriteProcessMemory_03bd {
  strings:
    $key_03bd = { 54 cf [2] 66 ed [2] 60 d8 [2] 4e d8 [2] 71 c4 }

  condition:
    any of them
}