rule TTP_XOR_WriteProcessMemory_cabd {
  strings:
    $key_cabd = { 9d cf [2] af ed [2] a9 d8 [2] 87 d8 [2] b8 c4 }

  condition:
    any of them
}