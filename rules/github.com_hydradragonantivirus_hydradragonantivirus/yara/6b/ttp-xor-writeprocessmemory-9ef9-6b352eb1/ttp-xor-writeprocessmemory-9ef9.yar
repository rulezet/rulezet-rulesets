rule TTP_XOR_WriteProcessMemory_9ef9 {
  strings:
    $key_9ef9 = { c9 8b [2] fb a9 [2] fd 9c [2] d3 9c [2] ec 80 }

  condition:
    any of them
}