rule TTP_XOR_WriteProcessMemory_9860 {
  strings:
    $key_9860 = { cf 12 [2] fd 30 [2] fb 05 [2] d5 05 [2] ea 19 }

  condition:
    any of them
}