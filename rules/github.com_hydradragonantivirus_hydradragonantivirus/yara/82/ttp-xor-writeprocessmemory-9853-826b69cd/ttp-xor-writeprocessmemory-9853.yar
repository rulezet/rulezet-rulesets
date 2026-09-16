rule TTP_XOR_WriteProcessMemory_9853 {
  strings:
    $key_9853 = { cf 21 [2] fd 03 [2] fb 36 [2] d5 36 [2] ea 2a }

  condition:
    any of them
}