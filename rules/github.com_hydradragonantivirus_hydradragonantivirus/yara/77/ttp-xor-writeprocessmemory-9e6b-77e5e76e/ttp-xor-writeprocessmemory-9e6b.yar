rule TTP_XOR_WriteProcessMemory_9e6b {
  strings:
    $key_9e6b = { c9 19 [2] fb 3b [2] fd 0e [2] d3 0e [2] ec 12 }

  condition:
    any of them
}