rule TTP_XOR_WriteProcessMemory_9eac {
  strings:
    $key_9eac = { c9 de [2] fb fc [2] fd c9 [2] d3 c9 [2] ec d5 }

  condition:
    any of them
}