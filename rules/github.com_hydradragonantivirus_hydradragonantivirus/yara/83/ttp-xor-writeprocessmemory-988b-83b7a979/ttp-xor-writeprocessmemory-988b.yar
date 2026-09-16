rule TTP_XOR_WriteProcessMemory_988b {
  strings:
    $key_988b = { cf f9 [2] fd db [2] fb ee [2] d5 ee [2] ea f2 }

  condition:
    any of them
}