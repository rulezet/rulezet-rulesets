rule TTP_XOR_WriteProcessMemory_9ea5 {
  strings:
    $key_9ea5 = { c9 d7 [2] fb f5 [2] fd c0 [2] d3 c0 [2] ec dc }

  condition:
    any of them
}