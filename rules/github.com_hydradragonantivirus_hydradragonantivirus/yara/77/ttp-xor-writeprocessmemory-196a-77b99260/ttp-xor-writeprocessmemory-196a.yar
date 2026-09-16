rule TTP_XOR_WriteProcessMemory_196a {
  strings:
    $key_196a = { 4e 18 [2] 7c 3a [2] 7a 0f [2] 54 0f [2] 6b 13 }

  condition:
    any of them
}