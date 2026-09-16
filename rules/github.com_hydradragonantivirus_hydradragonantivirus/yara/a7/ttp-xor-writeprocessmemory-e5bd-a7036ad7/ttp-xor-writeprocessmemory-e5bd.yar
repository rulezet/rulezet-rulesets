rule TTP_XOR_WriteProcessMemory_e5bd {
  strings:
    $key_e5bd = { b2 cf [2] 80 ed [2] 86 d8 [2] a8 d8 [2] 97 c4 }

  condition:
    any of them
}