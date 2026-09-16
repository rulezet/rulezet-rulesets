rule TTP_XOR_WriteProcessMemory_7f6a {
  strings:
    $key_7f6a = { 28 18 [2] 1a 3a [2] 1c 0f [2] 32 0f [2] 0d 13 }

  condition:
    any of them
}