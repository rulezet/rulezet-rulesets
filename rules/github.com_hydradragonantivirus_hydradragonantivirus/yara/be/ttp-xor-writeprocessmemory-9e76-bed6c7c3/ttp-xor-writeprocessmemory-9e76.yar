rule TTP_XOR_WriteProcessMemory_9e76 {
  strings:
    $key_9e76 = { c9 04 [2] fb 26 [2] fd 13 [2] d3 13 [2] ec 0f }

  condition:
    any of them
}