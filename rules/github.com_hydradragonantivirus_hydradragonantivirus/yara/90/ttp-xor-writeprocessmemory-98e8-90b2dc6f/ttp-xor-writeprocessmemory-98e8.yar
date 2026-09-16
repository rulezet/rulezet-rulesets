rule TTP_XOR_WriteProcessMemory_98e8 {
  strings:
    $key_98e8 = { cf 9a [2] fd b8 [2] fb 8d [2] d5 8d [2] ea 91 }

  condition:
    any of them
}