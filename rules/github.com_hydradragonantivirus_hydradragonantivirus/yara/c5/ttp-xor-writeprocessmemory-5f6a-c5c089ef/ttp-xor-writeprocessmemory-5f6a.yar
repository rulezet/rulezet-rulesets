rule TTP_XOR_WriteProcessMemory_5f6a {
  strings:
    $key_5f6a = { 08 18 [2] 3a 3a [2] 3c 0f [2] 12 0f [2] 2d 13 }

  condition:
    any of them
}