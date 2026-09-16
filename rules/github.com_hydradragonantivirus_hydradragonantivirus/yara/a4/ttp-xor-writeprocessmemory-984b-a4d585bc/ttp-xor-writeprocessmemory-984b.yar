rule TTP_XOR_WriteProcessMemory_984b {
  strings:
    $key_984b = { cf 39 [2] fd 1b [2] fb 2e [2] d5 2e [2] ea 32 }

  condition:
    any of them
}