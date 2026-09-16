rule TTP_XOR_WriteProcessMemory_9e8b {
  strings:
    $key_9e8b = { c9 f9 [2] fb db [2] fd ee [2] d3 ee [2] ec f2 }

  condition:
    any of them
}