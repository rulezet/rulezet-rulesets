rule TTP_XOR_WriteProcessMemory_983d {
  strings:
    $key_983d = { cf 4f [2] fd 6d [2] fb 58 [2] d5 58 [2] ea 44 }

  condition:
    any of them
}