rule TTP_XOR_WriteProcessMemory_9e65 {
  strings:
    $key_9e65 = { c9 17 [2] fb 35 [2] fd 00 [2] d3 00 [2] ec 1c }

  condition:
    any of them
}