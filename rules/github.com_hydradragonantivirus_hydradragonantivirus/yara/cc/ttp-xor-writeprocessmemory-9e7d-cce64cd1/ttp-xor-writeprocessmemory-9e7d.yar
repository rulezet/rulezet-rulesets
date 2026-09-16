rule TTP_XOR_WriteProcessMemory_9e7d {
  strings:
    $key_9e7d = { c9 0f [2] fb 2d [2] fd 18 [2] d3 18 [2] ec 04 }

  condition:
    any of them
}