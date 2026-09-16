rule TTP_XOR_WriteProcessMemory_b7bd {
  strings:
    $key_b7bd = { e0 cf [2] d2 ed [2] d4 d8 [2] fa d8 [2] c5 c4 }

  condition:
    any of them
}