rule TTP_XOR_WriteProcessMemory_9e25 {
  strings:
    $key_9e25 = { c9 57 [2] fb 75 [2] fd 40 [2] d3 40 [2] ec 5c }

  condition:
    any of them
}