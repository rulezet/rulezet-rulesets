rule TTP_XOR_WriteProcessMemory_9847 {
  strings:
    $key_9847 = { cf 35 [2] fd 17 [2] fb 22 [2] d5 22 [2] ea 3e }

  condition:
    any of them
}