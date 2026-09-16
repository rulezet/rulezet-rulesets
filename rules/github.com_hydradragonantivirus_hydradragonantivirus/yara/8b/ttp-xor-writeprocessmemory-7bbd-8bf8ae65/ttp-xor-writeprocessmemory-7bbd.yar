rule TTP_XOR_WriteProcessMemory_7bbd {
  strings:
    $key_7bbd = { 2c cf [2] 1e ed [2] 18 d8 [2] 36 d8 [2] 09 c4 }

  condition:
    any of them
}