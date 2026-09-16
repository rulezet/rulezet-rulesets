rule TTP_XOR_WriteProcessMemory_5d6a {
  strings:
    $key_5d6a = { 0a 18 [2] 38 3a [2] 3e 0f [2] 10 0f [2] 2f 13 }

  condition:
    any of them
}