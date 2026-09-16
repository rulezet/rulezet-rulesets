rule TTP_XOR_WriteProcessMemory_9ea3 {
  strings:
    $key_9ea3 = { c9 d1 [2] fb f3 [2] fd c6 [2] d3 c6 [2] ec da }

  condition:
    any of them
}