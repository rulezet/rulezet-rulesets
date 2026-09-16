rule TTP_XOR_WriteProcessMemory_aabd {
  strings:
    $key_aabd = { fd cf [2] cf ed [2] c9 d8 [2] e7 d8 [2] d8 c4 }

  condition:
    any of them
}