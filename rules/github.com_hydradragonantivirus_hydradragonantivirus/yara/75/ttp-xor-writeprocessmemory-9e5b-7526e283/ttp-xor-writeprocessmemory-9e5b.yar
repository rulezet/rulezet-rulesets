rule TTP_XOR_WriteProcessMemory_9e5b {
  strings:
    $key_9e5b = { c9 29 [2] fb 0b [2] fd 3e [2] d3 3e [2] ec 22 }

  condition:
    any of them
}