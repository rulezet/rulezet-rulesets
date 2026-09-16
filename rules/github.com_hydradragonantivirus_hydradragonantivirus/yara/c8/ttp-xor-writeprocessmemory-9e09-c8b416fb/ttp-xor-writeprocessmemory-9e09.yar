rule TTP_XOR_WriteProcessMemory_9e09 {
  strings:
    $key_9e09 = { c9 7b [2] fb 59 [2] fd 6c [2] d3 6c [2] ec 70 }

  condition:
    any of them
}