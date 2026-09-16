rule TTP_XOR_WriteProcessMemory_31bd {
  strings:
    $key_31bd = { 66 cf [2] 54 ed [2] 52 d8 [2] 7c d8 [2] 43 c4 }

  condition:
    any of them
}