rule TTP_XOR_WriteProcessMemory_9e26 {
  strings:
    $key_9e26 = { c9 54 [2] fb 76 [2] fd 43 [2] d3 43 [2] ec 5f }

  condition:
    any of them
}