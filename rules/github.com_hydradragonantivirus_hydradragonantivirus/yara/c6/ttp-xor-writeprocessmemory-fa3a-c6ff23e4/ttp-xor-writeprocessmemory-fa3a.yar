rule TTP_XOR_WriteProcessMemory_fa3a {
  strings:
    $key_fa3a = { ad 48 [2] 9f 6a [2] 99 5f [2] b7 5f [2] 88 43 }

  condition:
    any of them
}