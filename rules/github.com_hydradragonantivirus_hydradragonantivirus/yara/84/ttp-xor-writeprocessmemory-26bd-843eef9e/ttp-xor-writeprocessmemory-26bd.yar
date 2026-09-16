rule TTP_XOR_WriteProcessMemory_26bd {
  strings:
    $key_26bd = { 71 cf [2] 43 ed [2] 45 d8 [2] 6b d8 [2] 54 c4 }

  condition:
    any of them
}