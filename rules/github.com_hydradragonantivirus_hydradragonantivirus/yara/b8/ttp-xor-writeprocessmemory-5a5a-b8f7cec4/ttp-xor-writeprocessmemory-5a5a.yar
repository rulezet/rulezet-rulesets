rule TTP_XOR_WriteProcessMemory_5a5a {
  strings:
    $key_5a5a = { 0d 28 [2] 3f 0a [2] 39 3f [2] 17 3f [2] 28 23 }

  condition:
    any of them
}