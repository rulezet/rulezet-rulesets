rule TTP_XOR_WriteProcessMemory_98fe {
  strings:
    $key_98fe = { cf 8c [2] fd ae [2] fb 9b [2] d5 9b [2] ea 87 }

  condition:
    any of them
}