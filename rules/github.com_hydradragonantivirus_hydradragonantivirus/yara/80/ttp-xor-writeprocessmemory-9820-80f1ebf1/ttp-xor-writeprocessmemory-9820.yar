rule TTP_XOR_WriteProcessMemory_9820 {
  strings:
    $key_9820 = { cf 52 [2] fd 70 [2] fb 45 [2] d5 45 [2] ea 59 }

  condition:
    any of them
}