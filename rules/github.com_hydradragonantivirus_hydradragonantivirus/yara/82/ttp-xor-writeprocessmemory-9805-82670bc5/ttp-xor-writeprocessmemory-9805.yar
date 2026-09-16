rule TTP_XOR_WriteProcessMemory_9805 {
  strings:
    $key_9805 = { cf 77 [2] fd 55 [2] fb 60 [2] d5 60 [2] ea 7c }

  condition:
    any of them
}