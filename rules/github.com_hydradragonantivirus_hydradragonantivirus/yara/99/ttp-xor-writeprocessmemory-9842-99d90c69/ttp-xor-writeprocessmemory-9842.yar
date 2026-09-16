rule TTP_XOR_WriteProcessMemory_9842 {
  strings:
    $key_9842 = { cf 30 [2] fd 12 [2] fb 27 [2] d5 27 [2] ea 3b }

  condition:
    any of them
}