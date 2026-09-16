rule TTP_XOR_WriteProcessMemory_1f5a {
  strings:
    $key_1f5a = { 48 28 [2] 7a 0a [2] 7c 3f [2] 52 3f [2] 6d 23 }

  condition:
    any of them
}