rule TTP_XOR_WriteProcessMemory_9827 {
  strings:
    $key_9827 = { cf 55 [2] fd 77 [2] fb 42 [2] d5 42 [2] ea 5e }

  condition:
    any of them
}