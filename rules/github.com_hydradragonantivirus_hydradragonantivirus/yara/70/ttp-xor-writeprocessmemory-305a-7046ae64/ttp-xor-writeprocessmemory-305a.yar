rule TTP_XOR_WriteProcessMemory_305a {
  strings:
    $key_305a = { 67 28 [2] 55 0a [2] 53 3f [2] 7d 3f [2] 42 23 }

  condition:
    any of them
}