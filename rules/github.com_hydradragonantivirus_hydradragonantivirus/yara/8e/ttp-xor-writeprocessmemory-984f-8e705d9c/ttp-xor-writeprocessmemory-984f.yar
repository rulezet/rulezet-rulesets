rule TTP_XOR_WriteProcessMemory_984f {
  strings:
    $key_984f = { cf 3d [2] fd 1f [2] fb 2a [2] d5 2a [2] ea 36 }

  condition:
    any of them
}