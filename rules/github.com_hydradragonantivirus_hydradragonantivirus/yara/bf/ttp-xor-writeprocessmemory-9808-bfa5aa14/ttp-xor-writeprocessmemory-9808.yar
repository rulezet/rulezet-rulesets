rule TTP_XOR_WriteProcessMemory_9808 {
  strings:
    $key_9808 = { cf 7a [2] fd 58 [2] fb 6d [2] d5 6d [2] ea 71 }

  condition:
    any of them
}