rule TTP_XOR_WriteProcessMemory_41bd {
  strings:
    $key_41bd = { 16 cf [2] 24 ed [2] 22 d8 [2] 0c d8 [2] 33 c4 }

  condition:
    any of them
}