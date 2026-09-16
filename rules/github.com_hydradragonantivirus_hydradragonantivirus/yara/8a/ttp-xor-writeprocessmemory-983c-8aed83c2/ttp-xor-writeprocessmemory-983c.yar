rule TTP_XOR_WriteProcessMemory_983c {
  strings:
    $key_983c = { cf 4e [2] fd 6c [2] fb 59 [2] d5 59 [2] ea 45 }

  condition:
    any of them
}