rule TTP_XOR_WriteProcessMemory_699f {
  strings:
    $key_699f = { 3e ed [2] 0c cf [2] 0a fa [2] 24 fa [2] 1b e6 }

  condition:
    any of them
}