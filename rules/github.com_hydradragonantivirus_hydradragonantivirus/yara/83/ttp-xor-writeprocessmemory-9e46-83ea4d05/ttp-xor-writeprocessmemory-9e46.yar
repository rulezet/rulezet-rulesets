rule TTP_XOR_WriteProcessMemory_9e46 {
  strings:
    $key_9e46 = { c9 34 [2] fb 16 [2] fd 23 [2] d3 23 [2] ec 3f }

  condition:
    any of them
}