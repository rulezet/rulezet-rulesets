rule TTP_XOR_WriteProcessMemory_9e18 {
  strings:
    $key_9e18 = { c9 6a [2] fb 48 [2] fd 7d [2] d3 7d [2] ec 61 }

  condition:
    any of them
}