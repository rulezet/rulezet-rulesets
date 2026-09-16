rule TTP_XOR_WriteProcessMemory_9e2e {
  strings:
    $key_9e2e = { c9 5c [2] fb 7e [2] fd 4b [2] d3 4b [2] ec 57 }

  condition:
    any of them
}