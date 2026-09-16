rule TTP_XOR_WriteProcessMemory_9e2f {
  strings:
    $key_9e2f = { c9 5d [2] fb 7f [2] fd 4a [2] d3 4a [2] ec 56 }

  condition:
    any of them
}