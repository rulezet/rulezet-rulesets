rule TTP_XOR_WriteProcessMemory_1a3a {
  strings:
    $key_1a3a = { 4d 48 [2] 7f 6a [2] 79 5f [2] 57 5f [2] 68 43 }

  condition:
    any of them
}