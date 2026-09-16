rule TTP_XOR_WriteProcessMemory_9e28 {
  strings:
    $key_9e28 = { c9 5a [2] fb 78 [2] fd 4d [2] d3 4d [2] ec 51 }

  condition:
    any of them
}