rule TTP_XOR_WriteProcessMemory_56bd {
  strings:
    $key_56bd = { 01 cf [2] 33 ed [2] 35 d8 [2] 1b d8 [2] 24 c4 }

  condition:
    any of them
}