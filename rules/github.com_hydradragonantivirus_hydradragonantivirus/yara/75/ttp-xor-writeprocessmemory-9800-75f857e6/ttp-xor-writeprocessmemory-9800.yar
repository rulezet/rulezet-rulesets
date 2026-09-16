rule TTP_XOR_WriteProcessMemory_9800 {
  strings:
    $key_9800 = { cf 72 [2] fd 50 [2] fb 65 [2] d5 65 [2] ea 79 }

  condition:
    any of them
}