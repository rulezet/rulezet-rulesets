rule TTP_XOR_WriteProcessMemory_7dbd {
  strings:
    $key_7dbd = { 2a cf [2] 18 ed [2] 1e d8 [2] 30 d8 [2] 0f c4 }

  condition:
    any of them
}