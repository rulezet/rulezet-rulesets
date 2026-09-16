rule TTP_XOR_WriteProcessMemory_9e5f {
  strings:
    $key_9e5f = { c9 2d [2] fb 0f [2] fd 3a [2] d3 3a [2] ec 26 }

  condition:
    any of them
}