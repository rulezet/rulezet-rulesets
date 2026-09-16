rule TTP_XOR_WriteProcessMemory_9e89 {
  strings:
    $key_9e89 = { c9 fb [2] fb d9 [2] fd ec [2] d3 ec [2] ec f0 }

  condition:
    any of them
}