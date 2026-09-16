rule TTP_XOR_WriteProcessMemory_5ebd {
  strings:
    $key_5ebd = { 09 cf [2] 3b ed [2] 3d d8 [2] 13 d8 [2] 2c c4 }

  condition:
    any of them
}