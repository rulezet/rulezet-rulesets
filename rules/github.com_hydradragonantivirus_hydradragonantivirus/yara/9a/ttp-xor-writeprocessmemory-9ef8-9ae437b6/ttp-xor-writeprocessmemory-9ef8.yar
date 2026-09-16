rule TTP_XOR_WriteProcessMemory_9ef8 {
  strings:
    $key_9ef8 = { c9 8a [2] fb a8 [2] fd 9d [2] d3 9d [2] ec 81 }

  condition:
    any of them
}