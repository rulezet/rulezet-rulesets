rule TTP_XOR_WriteProcessMemory_9822 {
  strings:
    $key_9822 = { cf 50 [2] fd 72 [2] fb 47 [2] d5 47 [2] ea 5b }

  condition:
    any of them
}