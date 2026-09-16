rule TTP_XOR_WriteProcessMemory_986f {
  strings:
    $key_986f = { cf 1d [2] fd 3f [2] fb 0a [2] d5 0a [2] ea 16 }

  condition:
    any of them
}