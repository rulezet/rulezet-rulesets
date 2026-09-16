rule TTP_XOR_WriteProcessMemory_9e3b {
  strings:
    $key_9e3b = { c9 49 [2] fb 6b [2] fd 5e [2] d3 5e [2] ec 42 }

  condition:
    any of them
}