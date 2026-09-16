rule TTP_XOR_WriteProcessMemory_9ea1 {
  strings:
    $key_9ea1 = { c9 d3 [2] fb f1 [2] fd c4 [2] d3 c4 [2] ec d8 }

  condition:
    any of them
}