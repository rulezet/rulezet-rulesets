rule TTP_XOR_WriteProcessMemory_175a {
  strings:
    $key_175a = { 40 28 [2] 72 0a [2] 74 3f [2] 5a 3f [2] 65 23 }

  condition:
    any of them
}