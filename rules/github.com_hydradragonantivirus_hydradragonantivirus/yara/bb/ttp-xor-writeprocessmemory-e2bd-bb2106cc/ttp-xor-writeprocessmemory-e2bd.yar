rule TTP_XOR_WriteProcessMemory_e2bd {
  strings:
    $key_e2bd = { b5 cf [2] 87 ed [2] 81 d8 [2] af d8 [2] 90 c4 }

  condition:
    any of them
}