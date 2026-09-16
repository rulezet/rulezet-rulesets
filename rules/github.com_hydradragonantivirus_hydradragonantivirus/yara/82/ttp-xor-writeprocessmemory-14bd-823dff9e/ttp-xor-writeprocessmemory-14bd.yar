rule TTP_XOR_WriteProcessMemory_14bd {
  strings:
    $key_14bd = { 43 cf [2] 71 ed [2] 77 d8 [2] 59 d8 [2] 66 c4 }

  condition:
    any of them
}