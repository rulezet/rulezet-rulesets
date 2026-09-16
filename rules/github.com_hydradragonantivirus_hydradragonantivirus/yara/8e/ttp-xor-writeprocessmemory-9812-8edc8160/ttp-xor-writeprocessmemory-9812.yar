rule TTP_XOR_WriteProcessMemory_9812 {
  strings:
    $key_9812 = { cf 60 [2] fd 42 [2] fb 77 [2] d5 77 [2] ea 6b }

  condition:
    any of them
}