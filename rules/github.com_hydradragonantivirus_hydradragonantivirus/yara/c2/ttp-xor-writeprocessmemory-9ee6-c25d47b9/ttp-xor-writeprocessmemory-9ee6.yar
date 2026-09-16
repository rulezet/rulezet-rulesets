rule TTP_XOR_WriteProcessMemory_9ee6 {
  strings:
    $key_9ee6 = { c9 94 [2] fb b6 [2] fd 83 [2] d3 83 [2] ec 9f }

  condition:
    any of them
}