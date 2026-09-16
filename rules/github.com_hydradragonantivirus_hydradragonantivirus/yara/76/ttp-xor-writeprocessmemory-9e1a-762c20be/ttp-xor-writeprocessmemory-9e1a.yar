rule TTP_XOR_WriteProcessMemory_9e1a {
  strings:
    $key_9e1a = { c9 68 [2] fb 4a [2] fd 7f [2] d3 7f [2] ec 63 }

  condition:
    any of them
}