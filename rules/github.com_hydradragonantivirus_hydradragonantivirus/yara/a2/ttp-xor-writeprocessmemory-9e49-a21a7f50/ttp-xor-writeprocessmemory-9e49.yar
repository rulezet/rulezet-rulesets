rule TTP_XOR_WriteProcessMemory_9e49 {
  strings:
    $key_9e49 = { c9 3b [2] fb 19 [2] fd 2c [2] d3 2c [2] ec 30 }

  condition:
    any of them
}