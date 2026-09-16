rule TTP_XOR_WriteProcessMemory_9e0d {
  strings:
    $key_9e0d = { c9 7f [2] fb 5d [2] fd 68 [2] d3 68 [2] ec 74 }

  condition:
    any of them
}