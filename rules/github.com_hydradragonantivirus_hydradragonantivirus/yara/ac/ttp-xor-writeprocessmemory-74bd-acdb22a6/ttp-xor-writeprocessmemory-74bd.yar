rule TTP_XOR_WriteProcessMemory_74bd {
  strings:
    $key_74bd = { 23 cf [2] 11 ed [2] 17 d8 [2] 39 d8 [2] 06 c4 }

  condition:
    any of them
}