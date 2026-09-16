rule TTP_XOR_WriteProcessMemory_9e5c {
  strings:
    $key_9e5c = { c9 2e [2] fb 0c [2] fd 39 [2] d3 39 [2] ec 25 }

  condition:
    any of them
}