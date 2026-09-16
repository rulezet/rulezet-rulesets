rule TTP_XOR_WriteProcessMemory_0f4a {
  strings:
    $key_0f4a = { 58 38 [2] 6a 1a [2] 6c 2f [2] 42 2f [2] 7d 33 }

  condition:
    any of them
}