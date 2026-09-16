rule TTP_XOR_WriteProcessMemory_796a {
  strings:
    $key_796a = { 2e 18 [2] 1c 3a [2] 1a 0f [2] 34 0f [2] 0b 13 }

  condition:
    any of them
}