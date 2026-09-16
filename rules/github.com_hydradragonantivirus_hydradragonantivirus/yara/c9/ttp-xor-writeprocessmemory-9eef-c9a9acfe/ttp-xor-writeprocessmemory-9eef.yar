rule TTP_XOR_WriteProcessMemory_9eef {
  strings:
    $key_9eef = { c9 9d [2] fb bf [2] fd 8a [2] d3 8a [2] ec 96 }

  condition:
    any of them
}