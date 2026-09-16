rule TTP_XOR_WriteProcessMemory_6dbd {
  strings:
    $key_6dbd = { 3a cf [2] 08 ed [2] 0e d8 [2] 20 d8 [2] 1f c4 }

  condition:
    any of them
}