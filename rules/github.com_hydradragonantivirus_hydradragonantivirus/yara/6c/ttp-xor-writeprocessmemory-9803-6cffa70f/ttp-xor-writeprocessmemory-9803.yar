rule TTP_XOR_WriteProcessMemory_9803 {
  strings:
    $key_9803 = { cf 71 [2] fd 53 [2] fb 66 [2] d5 66 [2] ea 7a }

  condition:
    any of them
}