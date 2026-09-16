rule TTP_XOR_WriteProcessMemory_9864 {
  strings:
    $key_9864 = { cf 16 [2] fd 34 [2] fb 01 [2] d5 01 [2] ea 1d }

  condition:
    any of them
}