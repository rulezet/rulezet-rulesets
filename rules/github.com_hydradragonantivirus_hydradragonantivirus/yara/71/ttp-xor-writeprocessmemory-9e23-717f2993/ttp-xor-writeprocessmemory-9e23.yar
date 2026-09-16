rule TTP_XOR_WriteProcessMemory_9e23 {
  strings:
    $key_9e23 = { c9 51 [2] fb 73 [2] fd 46 [2] d3 46 [2] ec 5a }

  condition:
    any of them
}