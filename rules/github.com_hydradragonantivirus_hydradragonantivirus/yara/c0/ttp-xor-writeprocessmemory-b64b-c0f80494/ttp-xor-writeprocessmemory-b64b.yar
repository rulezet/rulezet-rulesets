rule TTP_XOR_WriteProcessMemory_b64b {
  strings:
    $key_b64b = { e1 39 [2] d3 1b [2] d5 2e [2] fb 2e [2] c4 32 }

  condition:
    any of them
}