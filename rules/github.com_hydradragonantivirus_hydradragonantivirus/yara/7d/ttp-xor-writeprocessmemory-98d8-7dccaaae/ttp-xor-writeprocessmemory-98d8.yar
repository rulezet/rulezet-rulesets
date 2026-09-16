rule TTP_XOR_WriteProcessMemory_98d8 {
  strings:
    $key_98d8 = { cf aa [2] fd 88 [2] fb bd [2] d5 bd [2] ea a1 }

  condition:
    any of them
}