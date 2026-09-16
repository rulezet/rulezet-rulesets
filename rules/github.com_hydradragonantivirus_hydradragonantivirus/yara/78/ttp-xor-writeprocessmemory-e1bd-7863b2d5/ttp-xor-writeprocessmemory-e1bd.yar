rule TTP_XOR_WriteProcessMemory_e1bd {
  strings:
    $key_e1bd = { b6 cf [2] 84 ed [2] 82 d8 [2] ac d8 [2] 93 c4 }

  condition:
    any of them
}