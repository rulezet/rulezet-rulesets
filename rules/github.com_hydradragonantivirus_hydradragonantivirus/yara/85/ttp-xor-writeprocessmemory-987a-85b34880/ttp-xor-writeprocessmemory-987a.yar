rule TTP_XOR_WriteProcessMemory_987a {
  strings:
    $key_987a = { cf 08 [2] fd 2a [2] fb 1f [2] d5 1f [2] ea 03 }

  condition:
    any of them
}