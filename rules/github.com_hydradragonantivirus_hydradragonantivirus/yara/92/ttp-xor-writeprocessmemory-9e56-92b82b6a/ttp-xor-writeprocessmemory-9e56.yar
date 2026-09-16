rule TTP_XOR_WriteProcessMemory_9e56 {
  strings:
    $key_9e56 = { c9 24 [2] fb 06 [2] fd 33 [2] d3 33 [2] ec 2f }

  condition:
    any of them
}