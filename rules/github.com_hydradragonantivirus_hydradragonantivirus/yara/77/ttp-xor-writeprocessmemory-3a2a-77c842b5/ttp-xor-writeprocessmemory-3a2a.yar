rule TTP_XOR_WriteProcessMemory_3a2a {
  strings:
    $key_3a2a = { 6d 58 [2] 5f 7a [2] 59 4f [2] 77 4f [2] 48 53 }

  condition:
    any of them
}