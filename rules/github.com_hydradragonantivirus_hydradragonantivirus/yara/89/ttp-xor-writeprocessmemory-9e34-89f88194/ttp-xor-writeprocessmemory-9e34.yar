rule TTP_XOR_WriteProcessMemory_9e34 {
  strings:
    $key_9e34 = { c9 46 [2] fb 64 [2] fd 51 [2] d3 51 [2] ec 4d }

  condition:
    any of them
}