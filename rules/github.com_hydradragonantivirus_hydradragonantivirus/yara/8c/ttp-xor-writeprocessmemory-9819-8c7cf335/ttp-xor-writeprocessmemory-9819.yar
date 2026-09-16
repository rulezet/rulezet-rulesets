rule TTP_XOR_WriteProcessMemory_9819 {
  strings:
    $key_9819 = { cf 6b [2] fd 49 [2] fb 7c [2] d5 7c [2] ea 60 }

  condition:
    any of them
}