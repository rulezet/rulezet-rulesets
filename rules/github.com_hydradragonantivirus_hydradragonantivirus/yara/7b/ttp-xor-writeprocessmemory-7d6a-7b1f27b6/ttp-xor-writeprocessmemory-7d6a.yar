rule TTP_XOR_WriteProcessMemory_7d6a {
  strings:
    $key_7d6a = { 2a 18 [2] 18 3a [2] 1e 0f [2] 30 0f [2] 0f 13 }

  condition:
    any of them
}