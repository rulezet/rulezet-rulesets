rule TTP_XOR_WriteProcessMemory_9e2b {
  strings:
    $key_9e2b = { c9 59 [2] fb 7b [2] fd 4e [2] d3 4e [2] ec 52 }

  condition:
    any of them
}