rule TTP_XOR_WriteProcessMemory_9e6a {
  strings:
    $key_9e6a = { c9 18 [2] fb 3a [2] fd 0f [2] d3 0f [2] ec 13 }

  condition:
    any of them
}