rule TTP_XOR_WriteProcessMemory_9e20 {
  strings:
    $key_9e20 = { c9 52 [2] fb 70 [2] fd 45 [2] d3 45 [2] ec 59 }

  condition:
    any of them
}