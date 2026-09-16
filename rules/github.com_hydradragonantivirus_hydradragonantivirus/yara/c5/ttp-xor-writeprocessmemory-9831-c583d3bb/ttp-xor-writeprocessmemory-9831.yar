rule TTP_XOR_WriteProcessMemory_9831 {
  strings:
    $key_9831 = { cf 43 [2] fd 61 [2] fb 54 [2] d5 54 [2] ea 48 }

  condition:
    any of them
}