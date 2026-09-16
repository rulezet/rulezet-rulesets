rule TTP_XOR_WriteProcessMemory_303a {
  strings:
    $key_303a = { 67 48 [2] 55 6a [2] 53 5f [2] 7d 5f [2] 42 43 }

  condition:
    any of them
}