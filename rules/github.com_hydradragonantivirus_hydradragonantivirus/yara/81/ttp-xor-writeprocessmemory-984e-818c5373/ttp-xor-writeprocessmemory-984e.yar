rule TTP_XOR_WriteProcessMemory_984e {
  strings:
    $key_984e = { cf 3c [2] fd 1e [2] fb 2b [2] d5 2b [2] ea 37 }

  condition:
    any of them
}