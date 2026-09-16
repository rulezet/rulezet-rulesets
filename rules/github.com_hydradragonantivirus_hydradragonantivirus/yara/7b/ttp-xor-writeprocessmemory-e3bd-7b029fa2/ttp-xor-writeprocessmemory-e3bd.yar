rule TTP_XOR_WriteProcessMemory_e3bd {
  strings:
    $key_e3bd = { b4 cf [2] 86 ed [2] 80 d8 [2] ae d8 [2] 91 c4 }

  condition:
    any of them
}