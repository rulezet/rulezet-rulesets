rule TTP_XOR_WriteProcessMemory_9e5e {
  strings:
    $key_9e5e = { c9 2c [2] fb 0e [2] fd 3b [2] d3 3b [2] ec 27 }

  condition:
    any of them
}