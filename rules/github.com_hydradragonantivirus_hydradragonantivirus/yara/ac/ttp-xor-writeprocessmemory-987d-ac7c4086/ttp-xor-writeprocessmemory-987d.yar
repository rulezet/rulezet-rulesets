rule TTP_XOR_WriteProcessMemory_987d {
  strings:
    $key_987d = { cf 0f [2] fd 2d [2] fb 18 [2] d5 18 [2] ea 04 }

  condition:
    any of them
}