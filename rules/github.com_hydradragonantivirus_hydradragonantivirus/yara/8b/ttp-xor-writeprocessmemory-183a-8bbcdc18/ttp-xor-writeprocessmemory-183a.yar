rule TTP_XOR_WriteProcessMemory_183a {
  strings:
    $key_183a = { 4f 48 [2] 7d 6a [2] 7b 5f [2] 55 5f [2] 6a 43 }

  condition:
    any of them
}