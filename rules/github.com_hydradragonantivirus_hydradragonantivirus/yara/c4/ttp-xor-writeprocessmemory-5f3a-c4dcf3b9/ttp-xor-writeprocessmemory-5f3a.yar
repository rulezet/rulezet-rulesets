rule TTP_XOR_WriteProcessMemory_5f3a {
  strings:
    $key_5f3a = { 08 48 [2] 3a 6a [2] 3c 5f [2] 12 5f [2] 2d 43 }

  condition:
    any of them
}