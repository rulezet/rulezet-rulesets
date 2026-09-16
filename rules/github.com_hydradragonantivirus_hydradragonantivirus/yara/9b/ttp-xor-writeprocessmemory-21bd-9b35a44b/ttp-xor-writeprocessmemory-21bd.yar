rule TTP_XOR_WriteProcessMemory_21bd {
  strings:
    $key_21bd = { 76 cf [2] 44 ed [2] 42 d8 [2] 6c d8 [2] 53 c4 }

  condition:
    any of them
}