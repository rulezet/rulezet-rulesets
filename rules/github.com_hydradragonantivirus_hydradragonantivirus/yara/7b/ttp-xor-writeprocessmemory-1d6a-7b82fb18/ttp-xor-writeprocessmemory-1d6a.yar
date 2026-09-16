rule TTP_XOR_WriteProcessMemory_1d6a {
  strings:
    $key_1d6a = { 4a 18 [2] 78 3a [2] 7e 0f [2] 50 0f [2] 6f 13 }

  condition:
    any of them
}