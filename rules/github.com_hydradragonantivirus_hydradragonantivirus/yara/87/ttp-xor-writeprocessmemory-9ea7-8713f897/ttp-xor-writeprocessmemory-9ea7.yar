rule TTP_XOR_WriteProcessMemory_9ea7 {
  strings:
    $key_9ea7 = { c9 d5 [2] fb f7 [2] fd c2 [2] d3 c2 [2] ec de }

  condition:
    any of them
}