rule TTP_XOR_WriteProcessMemory_9e50 {
  strings:
    $key_9e50 = { c9 22 [2] fb 00 [2] fd 35 [2] d3 35 [2] ec 29 }

  condition:
    any of them
}