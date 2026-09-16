rule TTP_XOR_WriteProcessMemory_9e72 {
  strings:
    $key_9e72 = { c9 00 [2] fb 22 [2] fd 17 [2] d3 17 [2] ec 0b }

  condition:
    any of them
}