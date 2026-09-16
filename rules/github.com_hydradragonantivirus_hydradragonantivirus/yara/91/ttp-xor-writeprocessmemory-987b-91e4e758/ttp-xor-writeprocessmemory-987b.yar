rule TTP_XOR_WriteProcessMemory_987b {
  strings:
    $key_987b = { cf 09 [2] fd 2b [2] fb 1e [2] d5 1e [2] ea 02 }

  condition:
    any of them
}