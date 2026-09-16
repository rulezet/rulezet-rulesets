rule TTP_XOR_WriteProcessMemory_9862 {
  strings:
    $key_9862 = { cf 10 [2] fd 32 [2] fb 07 [2] d5 07 [2] ea 1b }

  condition:
    any of them
}