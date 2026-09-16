rule TTP_XOR_WriteProcessMemory_3a6a {
  strings:
    $key_3a6a = { 6d 18 [2] 5f 3a [2] 59 0f [2] 77 0f [2] 48 13 }

  condition:
    any of them
}