rule TTP_XOR_WriteProcessMemory_9868 {
  strings:
    $key_9868 = { cf 1a [2] fd 38 [2] fb 0d [2] d5 0d [2] ea 11 }

  condition:
    any of them
}