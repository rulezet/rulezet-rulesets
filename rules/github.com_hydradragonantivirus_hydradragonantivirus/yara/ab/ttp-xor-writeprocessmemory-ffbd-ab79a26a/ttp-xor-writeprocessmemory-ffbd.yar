rule TTP_XOR_WriteProcessMemory_ffbd {
  strings:
    $key_ffbd = { a8 cf [2] 9a ed [2] 9c d8 [2] b2 d8 [2] 8d c4 }

  condition:
    any of them
}