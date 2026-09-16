rule TTP_XOR_WriteProcessMemory_2bbd {
  strings:
    $key_2bbd = { 7c cf [2] 4e ed [2] 48 d8 [2] 66 d8 [2] 59 c4 }

  condition:
    any of them
}