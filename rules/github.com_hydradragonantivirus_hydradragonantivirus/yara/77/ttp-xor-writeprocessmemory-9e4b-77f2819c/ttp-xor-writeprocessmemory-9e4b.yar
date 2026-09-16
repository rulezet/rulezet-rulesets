rule TTP_XOR_WriteProcessMemory_9e4b {
  strings:
    $key_9e4b = { c9 39 [2] fb 1b [2] fd 2e [2] d3 2e [2] ec 32 }

  condition:
    any of them
}