rule TTP_XOR_WriteProcessMemory_63bd {
  strings:
    $key_63bd = { 34 cf [2] 06 ed [2] 00 d8 [2] 2e d8 [2] 11 c4 }

  condition:
    any of them
}