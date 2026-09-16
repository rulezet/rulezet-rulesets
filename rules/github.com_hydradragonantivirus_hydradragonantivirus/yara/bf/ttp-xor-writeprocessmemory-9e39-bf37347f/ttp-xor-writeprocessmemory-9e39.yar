rule TTP_XOR_WriteProcessMemory_9e39 {
  strings:
    $key_9e39 = { c9 4b [2] fb 69 [2] fd 5c [2] d3 5c [2] ec 40 }

  condition:
    any of them
}