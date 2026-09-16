rule TTP_XOR_WriteProcessMemory_9889 {
  strings:
    $key_9889 = { cf fb [2] fd d9 [2] fb ec [2] d5 ec [2] ea f0 }

  condition:
    any of them
}