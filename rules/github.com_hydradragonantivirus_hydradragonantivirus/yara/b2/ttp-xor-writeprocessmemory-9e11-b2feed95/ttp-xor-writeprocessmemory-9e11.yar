rule TTP_XOR_WriteProcessMemory_9e11 {
  strings:
    $key_9e11 = { c9 63 [2] fb 41 [2] fd 74 [2] d3 74 [2] ec 68 }

  condition:
    any of them
}