rule TTP_XOR_WriteProcessMemory_9e7e {
  strings:
    $key_9e7e = { c9 0c [2] fb 2e [2] fd 1b [2] d3 1b [2] ec 07 }

  condition:
    any of them
}