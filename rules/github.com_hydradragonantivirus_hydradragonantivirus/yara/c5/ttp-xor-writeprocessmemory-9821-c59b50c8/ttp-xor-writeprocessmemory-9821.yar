rule TTP_XOR_WriteProcessMemory_9821 {
  strings:
    $key_9821 = { cf 53 [2] fd 71 [2] fb 44 [2] d5 44 [2] ea 58 }

  condition:
    any of them
}