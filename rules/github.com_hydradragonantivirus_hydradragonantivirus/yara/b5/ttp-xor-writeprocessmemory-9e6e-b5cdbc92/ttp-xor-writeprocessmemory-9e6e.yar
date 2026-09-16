rule TTP_XOR_WriteProcessMemory_9e6e {
  strings:
    $key_9e6e = { c9 1c [2] fb 3e [2] fd 0b [2] d3 0b [2] ec 17 }

  condition:
    any of them
}