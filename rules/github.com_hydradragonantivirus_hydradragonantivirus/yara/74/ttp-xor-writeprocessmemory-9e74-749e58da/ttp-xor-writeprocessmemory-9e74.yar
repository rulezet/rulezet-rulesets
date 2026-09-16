rule TTP_XOR_WriteProcessMemory_9e74 {
  strings:
    $key_9e74 = { c9 06 [2] fb 24 [2] fd 11 [2] d3 11 [2] ec 0d }

  condition:
    any of them
}