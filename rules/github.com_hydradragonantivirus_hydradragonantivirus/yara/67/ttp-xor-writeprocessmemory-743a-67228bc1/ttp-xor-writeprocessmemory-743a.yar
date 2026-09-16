rule TTP_XOR_WriteProcessMemory_743a {
  strings:
    $key_743a = { 23 48 [2] 11 6a [2] 17 5f [2] 39 5f [2] 06 43 }

  condition:
    any of them
}