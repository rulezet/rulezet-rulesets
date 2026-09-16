rule TTP_XOR_WriteProcessMemory_9e71 {
  strings:
    $key_9e71 = { c9 03 [2] fb 21 [2] fd 14 [2] d3 14 [2] ec 08 }

  condition:
    any of them
}