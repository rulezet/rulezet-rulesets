rule TTP_XOR_WriteProcessMemory_1f6a {
  strings:
    $key_1f6a = { 48 18 [2] 7a 3a [2] 7c 0f [2] 52 0f [2] 6d 13 }

  condition:
    any of them
}