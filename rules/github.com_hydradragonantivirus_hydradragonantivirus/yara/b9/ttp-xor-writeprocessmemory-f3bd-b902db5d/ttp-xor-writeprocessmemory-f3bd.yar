rule TTP_XOR_WriteProcessMemory_f3bd {
  strings:
    $key_f3bd = { a4 cf [2] 96 ed [2] 90 d8 [2] be d8 [2] 81 c4 }

  condition:
    any of them
}