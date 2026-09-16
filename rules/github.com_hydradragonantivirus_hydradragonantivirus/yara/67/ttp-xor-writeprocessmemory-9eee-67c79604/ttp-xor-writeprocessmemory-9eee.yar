rule TTP_XOR_WriteProcessMemory_9eee {
  strings:
    $key_9eee = { c9 9c [2] fb be [2] fd 8b [2] d3 8b [2] ec 97 }

  condition:
    any of them
}