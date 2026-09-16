rule TTP_XOR_WriteProcessMemory_499f {
  strings:
    $key_499f = { 1e ed [2] 2c cf [2] 2a fa [2] 04 fa [2] 3b e6 }

  condition:
    any of them
}