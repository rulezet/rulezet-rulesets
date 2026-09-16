rule TTP_XOR_WriteProcessMemory_982f {
  strings:
    $key_982f = { cf 5d [2] fd 7f [2] fb 4a [2] d5 4a [2] ea 56 }

  condition:
    any of them
}