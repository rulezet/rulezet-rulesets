rule TTP_XOR_WriteProcessMemory_45bd {
  strings:
    $key_45bd = { 12 cf [2] 20 ed [2] 26 d8 [2] 08 d8 [2] 37 c4 }

  condition:
    any of them
}