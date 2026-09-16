rule TTP_XOR_WriteProcessMemory_0b6a {
  strings:
    $key_0b6a = { 5c 18 [2] 6e 3a [2] 68 0f [2] 46 0f [2] 79 13 }

  condition:
    any of them
}