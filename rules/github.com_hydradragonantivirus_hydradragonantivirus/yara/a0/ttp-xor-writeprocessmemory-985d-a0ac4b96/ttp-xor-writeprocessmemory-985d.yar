rule TTP_XOR_WriteProcessMemory_985d {
  strings:
    $key_985d = { cf 2f [2] fd 0d [2] fb 38 [2] d5 38 [2] ea 24 }

  condition:
    any of them
}