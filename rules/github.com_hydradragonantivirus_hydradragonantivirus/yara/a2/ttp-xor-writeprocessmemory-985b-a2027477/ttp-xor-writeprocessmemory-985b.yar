rule TTP_XOR_WriteProcessMemory_985b {
  strings:
    $key_985b = { cf 29 [2] fd 0b [2] fb 3e [2] d5 3e [2] ea 22 }

  condition:
    any of them
}