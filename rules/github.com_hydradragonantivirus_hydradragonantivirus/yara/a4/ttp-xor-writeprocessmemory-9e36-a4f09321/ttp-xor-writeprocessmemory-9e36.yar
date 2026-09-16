rule TTP_XOR_WriteProcessMemory_9e36 {
  strings:
    $key_9e36 = { c9 44 [2] fb 66 [2] fd 53 [2] d3 53 [2] ec 4f }

  condition:
    any of them
}