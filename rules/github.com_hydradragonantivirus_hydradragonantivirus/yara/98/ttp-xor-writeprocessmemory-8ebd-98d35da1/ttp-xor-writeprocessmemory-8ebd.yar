rule TTP_XOR_WriteProcessMemory_8ebd {
  strings:
    $key_8ebd = { d9 cf [2] eb ed [2] ed d8 [2] c3 d8 [2] fc c4 }

  condition:
    any of them
}