rule TTP_XOR_WriteProcessMemory_299f {
  strings:
    $key_299f = { 7e ed [2] 4c cf [2] 4a fa [2] 64 fa [2] 5b e6 }

  condition:
    any of them
}