rule TTP_XOR_WriteProcessMemory_9e06 {
  strings:
    $key_9e06 = { c9 74 [2] fb 56 [2] fd 63 [2] d3 63 [2] ec 7f }

  condition:
    any of them
}