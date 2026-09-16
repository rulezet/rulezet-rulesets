rule TTP_XOR_WriteProcessMemory_66bd {
  strings:
    $key_66bd = { 31 cf [2] 03 ed [2] 05 d8 [2] 2b d8 [2] 14 c4 }

  condition:
    any of them
}