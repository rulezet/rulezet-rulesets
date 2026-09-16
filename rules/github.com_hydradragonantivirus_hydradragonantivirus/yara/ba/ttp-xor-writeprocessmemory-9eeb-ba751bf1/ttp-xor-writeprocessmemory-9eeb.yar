rule TTP_XOR_WriteProcessMemory_9eeb {
  strings:
    $key_9eeb = { c9 99 [2] fb bb [2] fd 8e [2] d3 8e [2] ec 92 }

  condition:
    any of them
}