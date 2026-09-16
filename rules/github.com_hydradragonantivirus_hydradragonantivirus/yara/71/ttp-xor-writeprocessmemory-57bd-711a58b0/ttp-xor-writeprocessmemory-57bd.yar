rule TTP_XOR_WriteProcessMemory_57bd {
  strings:
    $key_57bd = { 00 cf [2] 32 ed [2] 34 d8 [2] 1a d8 [2] 25 c4 }

  condition:
    any of them
}