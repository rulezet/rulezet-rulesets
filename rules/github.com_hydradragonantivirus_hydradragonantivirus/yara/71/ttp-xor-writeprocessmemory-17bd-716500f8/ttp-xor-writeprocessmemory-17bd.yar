rule TTP_XOR_WriteProcessMemory_17bd {
  strings:
    $key_17bd = { 40 cf [2] 72 ed [2] 74 d8 [2] 5a d8 [2] 65 c4 }

  condition:
    any of them
}