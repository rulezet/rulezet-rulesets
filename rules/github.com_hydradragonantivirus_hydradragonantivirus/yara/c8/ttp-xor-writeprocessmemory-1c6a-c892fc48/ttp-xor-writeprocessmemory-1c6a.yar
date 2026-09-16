rule TTP_XOR_WriteProcessMemory_1c6a {
  strings:
    $key_1c6a = { 4b 18 [2] 79 3a [2] 7f 0f [2] 51 0f [2] 6e 13 }

  condition:
    any of them
}