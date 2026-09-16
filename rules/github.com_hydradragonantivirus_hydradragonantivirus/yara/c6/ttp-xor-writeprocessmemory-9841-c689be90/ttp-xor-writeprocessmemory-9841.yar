rule TTP_XOR_WriteProcessMemory_9841 {
  strings:
    $key_9841 = { cf 33 [2] fd 11 [2] fb 24 [2] d5 24 [2] ea 38 }

  condition:
    any of them
}