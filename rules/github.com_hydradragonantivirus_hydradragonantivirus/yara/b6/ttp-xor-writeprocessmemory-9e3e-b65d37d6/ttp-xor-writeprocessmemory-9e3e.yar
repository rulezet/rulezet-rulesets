rule TTP_XOR_WriteProcessMemory_9e3e {
  strings:
    $key_9e3e = { c9 4c [2] fb 6e [2] fd 5b [2] d3 5b [2] ec 47 }

  condition:
    any of them
}