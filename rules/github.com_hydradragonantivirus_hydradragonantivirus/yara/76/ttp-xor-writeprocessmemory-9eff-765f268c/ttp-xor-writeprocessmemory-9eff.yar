rule TTP_XOR_WriteProcessMemory_9eff {
  strings:
    $key_9eff = { c9 8d [2] fb af [2] fd 9a [2] d3 9a [2] ec 86 }

  condition:
    any of them
}