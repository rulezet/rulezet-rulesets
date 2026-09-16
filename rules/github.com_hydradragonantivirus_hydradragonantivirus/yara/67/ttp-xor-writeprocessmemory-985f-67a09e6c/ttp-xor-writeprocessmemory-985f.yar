rule TTP_XOR_WriteProcessMemory_985f {
  strings:
    $key_985f = { cf 2d [2] fd 0f [2] fb 3a [2] d5 3a [2] ea 26 }

  condition:
    any of them
}