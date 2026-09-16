rule TTP_XOR_WriteProcessMemory_9e33 {
  strings:
    $key_9e33 = { c9 41 [2] fb 63 [2] fd 56 [2] d3 56 [2] ec 4a }

  condition:
    any of them
}