rule TTP_XOR_WriteProcessMemory_25bd {
  strings:
    $key_25bd = { 72 cf [2] 40 ed [2] 46 d8 [2] 68 d8 [2] 57 c4 }

  condition:
    any of them
}