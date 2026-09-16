rule TTP_XOR_WriteProcessMemory_6ebd {
  strings:
    $key_6ebd = { 39 cf [2] 0b ed [2] 0d d8 [2] 23 d8 [2] 1c c4 }

  condition:
    any of them
}