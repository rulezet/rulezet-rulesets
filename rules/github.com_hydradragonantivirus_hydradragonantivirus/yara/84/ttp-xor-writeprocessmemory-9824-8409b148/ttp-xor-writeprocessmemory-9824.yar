rule TTP_XOR_WriteProcessMemory_9824 {
  strings:
    $key_9824 = { cf 56 [2] fd 74 [2] fb 41 [2] d5 41 [2] ea 5d }

  condition:
    any of them
}