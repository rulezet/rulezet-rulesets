rule TTP_XOR_WriteProcessMemory_9eec {
  strings:
    $key_9eec = { c9 9e [2] fb bc [2] fd 89 [2] d3 89 [2] ec 95 }

  condition:
    any of them
}