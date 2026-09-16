rule TTP_XOR_WriteProcessMemory_984d {
  strings:
    $key_984d = { cf 3f [2] fd 1d [2] fb 28 [2] d5 28 [2] ea 34 }

  condition:
    any of them
}