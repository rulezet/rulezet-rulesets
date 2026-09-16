rule TTP_XOR_WriteProcessMemory_9850 {
  strings:
    $key_9850 = { cf 22 [2] fd 00 [2] fb 35 [2] d5 35 [2] ea 29 }

  condition:
    any of them
}