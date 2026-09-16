rule TTP_XOR_WriteProcessMemory_9834 {
  strings:
    $key_9834 = { cf 46 [2] fd 64 [2] fb 51 [2] d5 51 [2] ea 4d }

  condition:
    any of them
}