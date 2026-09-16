rule TTP_XOR_WriteProcessMemory_982b {
  strings:
    $key_982b = { cf 59 [2] fd 7b [2] fb 4e [2] d5 4e [2] ea 52 }

  condition:
    any of them
}