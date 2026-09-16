rule TTP_XOR_WriteProcessMemory_1bbd {
  strings:
    $key_1bbd = { 4c cf [2] 7e ed [2] 78 d8 [2] 56 d8 [2] 69 c4 }

  condition:
    any of them
}