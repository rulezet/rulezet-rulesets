rule TTP_XOR_WriteProcessMemory_9878 {
  strings:
    $key_9878 = { cf 0a [2] fd 28 [2] fb 1d [2] d5 1d [2] ea 01 }

  condition:
    any of them
}