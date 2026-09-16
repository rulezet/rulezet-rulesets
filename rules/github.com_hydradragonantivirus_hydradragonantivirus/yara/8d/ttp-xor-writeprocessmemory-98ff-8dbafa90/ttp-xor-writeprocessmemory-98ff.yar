rule TTP_XOR_WriteProcessMemory_98ff {
  strings:
    $key_98ff = { cf 8d [2] fd af [2] fb 9a [2] d5 9a [2] ea 86 }

  condition:
    any of them
}