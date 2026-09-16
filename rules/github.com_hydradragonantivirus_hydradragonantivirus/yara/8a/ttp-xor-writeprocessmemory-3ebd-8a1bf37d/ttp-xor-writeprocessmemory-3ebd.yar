rule TTP_XOR_WriteProcessMemory_3ebd {
  strings:
    $key_3ebd = { 69 cf [2] 5b ed [2] 5d d8 [2] 73 d8 [2] 4c c4 }

  condition:
    any of them
}