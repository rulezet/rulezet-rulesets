rule TTP_XOR_WriteProcessMemory_3a1a {
  strings:
    $key_3a1a = { 6d 68 [2] 5f 4a [2] 59 7f [2] 77 7f [2] 48 63 }

  condition:
    any of them
}