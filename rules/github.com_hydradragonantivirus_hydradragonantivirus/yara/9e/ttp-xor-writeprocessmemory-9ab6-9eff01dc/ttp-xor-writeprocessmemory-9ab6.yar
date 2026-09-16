rule TTP_XOR_WriteProcessMemory_9ab6 {
  strings:
    $key_9ab6 = { cd c4 [2] ff e6 [2] f9 d3 [2] d7 d3 [2] e8 cf }

  condition:
    any of them
}