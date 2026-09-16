rule TTP_XOR_WriteProcessMemory_9843 {
  strings:
    $key_9843 = { cf 31 [2] fd 13 [2] fb 26 [2] d5 26 [2] ea 3a }

  condition:
    any of them
}