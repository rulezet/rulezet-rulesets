rule TTP_XOR_WriteProcessMemory_186a {
  strings:
    $key_186a = { 4f 18 [2] 7d 3a [2] 7b 0f [2] 55 0f [2] 6a 13 }

  condition:
    any of them
}