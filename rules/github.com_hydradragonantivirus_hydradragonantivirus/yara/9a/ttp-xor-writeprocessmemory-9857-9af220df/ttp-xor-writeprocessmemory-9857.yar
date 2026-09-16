rule TTP_XOR_WriteProcessMemory_9857 {
  strings:
    $key_9857 = { cf 25 [2] fd 07 [2] fb 32 [2] d5 32 [2] ea 2e }

  condition:
    any of them
}