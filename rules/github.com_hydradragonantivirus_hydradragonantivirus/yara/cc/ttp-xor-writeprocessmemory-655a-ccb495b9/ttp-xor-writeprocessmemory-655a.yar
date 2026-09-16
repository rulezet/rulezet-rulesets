rule TTP_XOR_WriteProcessMemory_655a {
  strings:
    $key_655a = { 32 28 [2] 00 0a [2] 06 3f [2] 28 3f [2] 17 23 }

  condition:
    any of them
}