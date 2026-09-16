rule TTP_XOR_WriteProcessMemory_b2bd {
  strings:
    $key_b2bd = { e5 cf [2] d7 ed [2] d1 d8 [2] ff d8 [2] c0 c4 }

  condition:
    any of them
}