rule TTP_XOR_WriteProcessMemory_9859 {
  strings:
    $key_9859 = { cf 2b [2] fd 09 [2] fb 3c [2] d5 3c [2] ea 20 }

  condition:
    any of them
}