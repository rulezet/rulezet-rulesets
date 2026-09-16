rule TTP_XOR_WriteProcessMemory_9e59 {
  strings:
    $key_9e59 = { c9 2b [2] fb 09 [2] fd 3c [2] d3 3c [2] ec 20 }

  condition:
    any of them
}