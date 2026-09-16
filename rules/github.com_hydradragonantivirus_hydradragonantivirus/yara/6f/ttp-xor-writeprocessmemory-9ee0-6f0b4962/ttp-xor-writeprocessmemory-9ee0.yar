rule TTP_XOR_WriteProcessMemory_9ee0 {
  strings:
    $key_9ee0 = { c9 92 [2] fb b0 [2] fd 85 [2] d3 85 [2] ec 99 }

  condition:
    any of them
}