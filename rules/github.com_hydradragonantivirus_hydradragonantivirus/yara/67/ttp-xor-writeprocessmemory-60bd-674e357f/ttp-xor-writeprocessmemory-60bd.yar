rule TTP_XOR_WriteProcessMemory_60bd {
  strings:
    $key_60bd = { 37 cf [2] 05 ed [2] 03 d8 [2] 2d d8 [2] 12 c4 }

  condition:
    any of them
}