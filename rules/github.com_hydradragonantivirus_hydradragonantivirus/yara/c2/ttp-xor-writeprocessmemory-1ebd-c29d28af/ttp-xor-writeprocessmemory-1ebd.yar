rule TTP_XOR_WriteProcessMemory_1ebd {
  strings:
    $key_1ebd = { 49 cf [2] 7b ed [2] 7d d8 [2] 53 d8 [2] 6c c4 }

  condition:
    any of them
}