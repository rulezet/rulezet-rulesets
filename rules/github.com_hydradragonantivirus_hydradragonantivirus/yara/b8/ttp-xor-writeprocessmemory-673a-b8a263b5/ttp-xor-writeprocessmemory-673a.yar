rule TTP_XOR_WriteProcessMemory_673a {
  strings:
    $key_673a = { 30 48 [2] 02 6a [2] 04 5f [2] 2a 5f [2] 15 43 }

  condition:
    any of them
}