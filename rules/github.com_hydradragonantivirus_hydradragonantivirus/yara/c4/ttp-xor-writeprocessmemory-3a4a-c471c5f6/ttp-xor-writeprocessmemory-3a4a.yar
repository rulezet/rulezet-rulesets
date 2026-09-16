rule TTP_XOR_WriteProcessMemory_3a4a {
  strings:
    $key_3a4a = { 6d 38 [2] 5f 1a [2] 59 2f [2] 77 2f [2] 48 33 }

  condition:
    any of them
}