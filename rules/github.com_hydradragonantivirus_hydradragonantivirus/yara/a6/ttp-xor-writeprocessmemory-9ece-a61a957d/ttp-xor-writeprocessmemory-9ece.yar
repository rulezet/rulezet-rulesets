rule TTP_XOR_WriteProcessMemory_9ece {
  strings:
    $key_9ece = { c9 bc [2] fb 9e [2] fd ab [2] d3 ab [2] ec b7 }

  condition:
    any of them
}