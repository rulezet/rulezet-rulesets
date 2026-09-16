rule TTP_XOR_WriteProcessMemory_9e24 {
  strings:
    $key_9e24 = { c9 56 [2] fb 74 [2] fd 41 [2] d3 41 [2] ec 5d }

  condition:
    any of them
}