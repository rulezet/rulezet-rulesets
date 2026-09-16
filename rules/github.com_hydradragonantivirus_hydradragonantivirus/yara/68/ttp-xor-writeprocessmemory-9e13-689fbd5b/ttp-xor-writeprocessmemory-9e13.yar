rule TTP_XOR_WriteProcessMemory_9e13 {
  strings:
    $key_9e13 = { c9 61 [2] fb 43 [2] fd 76 [2] d3 76 [2] ec 6a }

  condition:
    any of them
}