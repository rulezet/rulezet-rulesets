rule TTP_XOR_WriteProcessMemory_5b5a {
  strings:
    $key_5b5a = { 0c 28 [2] 3e 0a [2] 38 3f [2] 16 3f [2] 29 23 }

  condition:
    any of them
}