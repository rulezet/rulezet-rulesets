rule TTP_XOR_WriteProcessMemory_3a5a {
  strings:
    $key_3a5a = { 6d 28 [2] 5f 0a [2] 59 3f [2] 77 3f [2] 48 23 }

  condition:
    any of them
}