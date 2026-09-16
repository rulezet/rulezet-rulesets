rule TTP_XOR_WriteProcessMemory_9ee8 {
  strings:
    $key_9ee8 = { c9 9a [2] fb b8 [2] fd 8d [2] d3 8d [2] ec 91 }

  condition:
    any of them
}