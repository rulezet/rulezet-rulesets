rule TTP_XOR_WriteProcessMemory_5b6a {
  strings:
    $key_5b6a = { 0c 18 [2] 3e 3a [2] 38 0f [2] 16 0f [2] 29 13 }

  condition:
    any of them
}