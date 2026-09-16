rule TTP_XOR_WriteProcessMemory_983f {
  strings:
    $key_983f = { cf 4d [2] fd 6f [2] fb 5a [2] d5 5a [2] ea 46 }

  condition:
    any of them
}