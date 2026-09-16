rule TTP_XOR_WriteProcessMemory_9efb {
  strings:
    $key_9efb = { c9 89 [2] fb ab [2] fd 9e [2] d3 9e [2] ec 82 }

  condition:
    any of them
}