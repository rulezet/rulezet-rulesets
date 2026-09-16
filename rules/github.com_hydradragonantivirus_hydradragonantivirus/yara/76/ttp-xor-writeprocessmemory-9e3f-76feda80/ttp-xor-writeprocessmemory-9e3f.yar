rule TTP_XOR_WriteProcessMemory_9e3f {
  strings:
    $key_9e3f = { c9 4d [2] fb 6f [2] fd 5a [2] d3 5a [2] ec 46 }

  condition:
    any of them
}