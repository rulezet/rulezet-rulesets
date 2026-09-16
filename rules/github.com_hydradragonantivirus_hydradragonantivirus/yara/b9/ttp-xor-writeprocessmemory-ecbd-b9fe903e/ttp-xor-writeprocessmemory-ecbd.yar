rule TTP_XOR_WriteProcessMemory_ecbd {
  strings:
    $key_ecbd = { bb cf [2] 89 ed [2] 8f d8 [2] a1 d8 [2] 9e c4 }

  condition:
    any of them
}