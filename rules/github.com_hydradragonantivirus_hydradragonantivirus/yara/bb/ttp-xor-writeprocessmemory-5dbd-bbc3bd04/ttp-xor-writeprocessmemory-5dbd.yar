rule TTP_XOR_WriteProcessMemory_5dbd {
  strings:
    $key_5dbd = { 0a cf [2] 38 ed [2] 3e d8 [2] 10 d8 [2] 2f c4 }

  condition:
    any of them
}