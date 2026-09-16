rule TTP_XOR_WriteProcessMemory_9830 {
  strings:
    $key_9830 = { cf 42 [2] fd 60 [2] fb 55 [2] d5 55 [2] ea 49 }

  condition:
    any of them
}