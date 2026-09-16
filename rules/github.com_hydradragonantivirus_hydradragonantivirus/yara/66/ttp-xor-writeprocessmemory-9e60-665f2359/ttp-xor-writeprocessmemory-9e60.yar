rule TTP_XOR_WriteProcessMemory_9e60 {
  strings:
    $key_9e60 = { c9 12 [2] fb 30 [2] fd 05 [2] d3 05 [2] ec 19 }

  condition:
    any of them
}