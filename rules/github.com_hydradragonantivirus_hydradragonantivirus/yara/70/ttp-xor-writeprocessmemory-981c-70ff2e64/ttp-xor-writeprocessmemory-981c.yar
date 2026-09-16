rule TTP_XOR_WriteProcessMemory_981c {
  strings:
    $key_981c = { cf 6e [2] fd 4c [2] fb 79 [2] d5 79 [2] ea 65 }

  condition:
    any of them
}