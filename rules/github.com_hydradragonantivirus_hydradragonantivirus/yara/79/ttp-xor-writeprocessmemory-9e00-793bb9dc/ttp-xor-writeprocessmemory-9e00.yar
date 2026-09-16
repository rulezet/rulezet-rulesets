rule TTP_XOR_WriteProcessMemory_9e00 {
  strings:
    $key_9e00 = { c9 72 [2] fb 50 [2] fd 65 [2] d3 65 [2] ec 79 }

  condition:
    any of them
}