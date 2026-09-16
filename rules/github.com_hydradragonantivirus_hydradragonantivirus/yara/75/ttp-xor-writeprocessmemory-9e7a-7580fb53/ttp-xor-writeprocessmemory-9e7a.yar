rule TTP_XOR_WriteProcessMemory_9e7a {
  strings:
    $key_9e7a = { c9 08 [2] fb 2a [2] fd 1f [2] d3 1f [2] ec 03 }

  condition:
    any of them
}