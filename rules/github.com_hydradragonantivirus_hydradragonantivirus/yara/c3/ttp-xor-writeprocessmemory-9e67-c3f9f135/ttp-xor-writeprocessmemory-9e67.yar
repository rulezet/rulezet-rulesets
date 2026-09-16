rule TTP_XOR_WriteProcessMemory_9e67 {
  strings:
    $key_9e67 = { c9 15 [2] fb 37 [2] fd 02 [2] d3 02 [2] ec 1e }

  condition:
    any of them
}