rule TTP_XOR_WriteProcessMemory_83bd {
  strings:
    $key_83bd = { d4 cf [2] e6 ed [2] e0 d8 [2] ce d8 [2] f1 c4 }

  condition:
    any of them
}