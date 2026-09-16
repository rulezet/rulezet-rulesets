rule TTP_XOR_WriteProcessMemory_9ee2 {
  strings:
    $key_9ee2 = { c9 90 [2] fb b2 [2] fd 87 [2] d3 87 [2] ec 9b }

  condition:
    any of them
}