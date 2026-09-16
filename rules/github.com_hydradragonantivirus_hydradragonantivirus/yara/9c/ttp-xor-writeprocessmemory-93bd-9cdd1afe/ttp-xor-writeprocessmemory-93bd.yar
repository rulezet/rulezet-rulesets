rule TTP_XOR_WriteProcessMemory_93bd {
  strings:
    $key_93bd = { c4 cf [2] f6 ed [2] f0 d8 [2] de d8 [2] e1 c4 }

  condition:
    any of them
}