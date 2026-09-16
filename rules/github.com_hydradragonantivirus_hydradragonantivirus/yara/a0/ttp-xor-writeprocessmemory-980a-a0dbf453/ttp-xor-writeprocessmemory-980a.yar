rule TTP_XOR_WriteProcessMemory_980a {
  strings:
    $key_980a = { cf 78 [2] fd 5a [2] fb 6f [2] d5 6f [2] ea 73 }

  condition:
    any of them
}