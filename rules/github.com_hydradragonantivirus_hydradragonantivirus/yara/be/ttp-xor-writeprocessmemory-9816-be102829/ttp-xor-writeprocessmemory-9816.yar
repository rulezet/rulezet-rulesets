rule TTP_XOR_WriteProcessMemory_9816 {
  strings:
    $key_9816 = { cf 64 [2] fd 46 [2] fb 73 [2] d5 73 [2] ea 6f }

  condition:
    any of them
}