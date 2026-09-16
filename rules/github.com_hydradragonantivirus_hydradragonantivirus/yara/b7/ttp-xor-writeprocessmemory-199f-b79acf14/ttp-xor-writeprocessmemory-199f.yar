rule TTP_XOR_WriteProcessMemory_199f {
  strings:
    $key_199f = { 4e ed [2] 7c cf [2] 7a fa [2] 54 fa [2] 6b e6 }

  condition:
    any of them
}