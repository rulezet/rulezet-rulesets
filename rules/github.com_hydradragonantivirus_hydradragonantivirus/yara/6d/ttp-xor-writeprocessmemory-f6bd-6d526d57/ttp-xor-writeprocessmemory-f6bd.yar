rule TTP_XOR_WriteProcessMemory_f6bd {
  strings:
    $key_f6bd = { a1 cf [2] 93 ed [2] 95 d8 [2] bb d8 [2] 84 c4 }

  condition:
    any of them
}