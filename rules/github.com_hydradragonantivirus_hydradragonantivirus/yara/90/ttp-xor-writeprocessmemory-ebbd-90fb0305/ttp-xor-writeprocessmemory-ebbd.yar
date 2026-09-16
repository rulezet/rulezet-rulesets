rule TTP_XOR_WriteProcessMemory_ebbd {
  strings:
    $key_ebbd = { bc cf [2] 8e ed [2] 88 d8 [2] a6 d8 [2] 99 c4 }

  condition:
    any of them
}