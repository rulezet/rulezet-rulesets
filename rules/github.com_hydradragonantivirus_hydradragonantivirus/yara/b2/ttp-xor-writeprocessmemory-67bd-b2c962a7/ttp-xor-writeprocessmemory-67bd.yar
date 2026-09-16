rule TTP_XOR_WriteProcessMemory_67bd {
  strings:
    $key_67bd = { 30 cf [2] 02 ed [2] 04 d8 [2] 2a d8 [2] 15 c4 }

  condition:
    any of them
}