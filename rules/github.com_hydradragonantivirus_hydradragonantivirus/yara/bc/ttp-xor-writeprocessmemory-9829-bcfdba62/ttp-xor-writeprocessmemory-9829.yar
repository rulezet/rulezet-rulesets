rule TTP_XOR_WriteProcessMemory_9829 {
  strings:
    $key_9829 = { cf 5b [2] fd 79 [2] fb 4c [2] d5 4c [2] ea 50 }

  condition:
    any of them
}