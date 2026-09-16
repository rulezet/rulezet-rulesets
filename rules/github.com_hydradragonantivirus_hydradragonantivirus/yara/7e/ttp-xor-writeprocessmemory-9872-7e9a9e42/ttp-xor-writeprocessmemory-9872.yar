rule TTP_XOR_WriteProcessMemory_9872 {
  strings:
    $key_9872 = { cf 00 [2] fd 22 [2] fb 17 [2] d5 17 [2] ea 0b }

  condition:
    any of them
}