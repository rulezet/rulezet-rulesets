rule TTP_XOR_WriteProcessMemory_9e51 {
  strings:
    $key_9e51 = { c9 23 [2] fb 01 [2] fd 34 [2] d3 34 [2] ec 28 }

  condition:
    any of them
}