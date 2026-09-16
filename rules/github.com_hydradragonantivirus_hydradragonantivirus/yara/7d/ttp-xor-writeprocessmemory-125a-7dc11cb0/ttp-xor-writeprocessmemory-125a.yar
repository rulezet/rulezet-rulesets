rule TTP_XOR_WriteProcessMemory_125a {
  strings:
    $key_125a = { 45 28 [2] 77 0a [2] 71 3f [2] 5f 3f [2] 60 23 }

  condition:
    any of them
}