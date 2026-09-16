rule TTP_XOR_WriteProcessMemory_9e0a {
  strings:
    $key_9e0a = { c9 78 [2] fb 5a [2] fd 6f [2] d3 6f [2] ec 73 }

  condition:
    any of them
}