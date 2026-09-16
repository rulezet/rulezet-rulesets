rule TTP_XOR_WriteProcessMemory_9eea {
  strings:
    $key_9eea = { c9 98 [2] fb ba [2] fd 8f [2] d3 8f [2] ec 93 }

  condition:
    any of them
}