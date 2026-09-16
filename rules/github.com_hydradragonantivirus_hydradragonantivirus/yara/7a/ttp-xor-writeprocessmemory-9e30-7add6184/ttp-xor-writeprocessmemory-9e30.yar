rule TTP_XOR_WriteProcessMemory_9e30 {
  strings:
    $key_9e30 = { c9 42 [2] fb 60 [2] fd 55 [2] d3 55 [2] ec 49 }

  condition:
    any of them
}