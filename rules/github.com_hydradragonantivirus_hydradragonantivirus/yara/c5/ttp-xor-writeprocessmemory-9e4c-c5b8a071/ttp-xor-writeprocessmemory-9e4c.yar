rule TTP_XOR_WriteProcessMemory_9e4c {
  strings:
    $key_9e4c = { c9 3e [2] fb 1c [2] fd 29 [2] d3 29 [2] ec 35 }

  condition:
    any of them
}