rule TTP_XOR_WriteProcessMemory_9867 {
  strings:
    $key_9867 = { cf 15 [2] fd 37 [2] fb 02 [2] d5 02 [2] ea 1e }

  condition:
    any of them
}