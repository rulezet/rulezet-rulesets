rule TTP_XOR_WriteProcessMemory_9e7b {
  strings:
    $key_9e7b = { c9 09 [2] fb 2b [2] fd 1e [2] d3 1e [2] ec 02 }

  condition:
    any of them
}