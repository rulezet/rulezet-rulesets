rule TTP_XOR_WriteProcessMemory_981b {
  strings:
    $key_981b = { cf 69 [2] fd 4b [2] fb 7e [2] d5 7e [2] ea 62 }

  condition:
    any of them
}