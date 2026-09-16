rule TTP_XOR_WriteProcessMemory_2dbd {
  strings:
    $key_2dbd = { 7a cf [2] 48 ed [2] 4e d8 [2] 60 d8 [2] 5f c4 }

  condition:
    any of them
}