rule TTP_XOR_WriteProcessMemory_98fa {
  strings:
    $key_98fa = { cf 88 [2] fd aa [2] fb 9f [2] d5 9f [2] ea 83 }

  condition:
    any of them
}