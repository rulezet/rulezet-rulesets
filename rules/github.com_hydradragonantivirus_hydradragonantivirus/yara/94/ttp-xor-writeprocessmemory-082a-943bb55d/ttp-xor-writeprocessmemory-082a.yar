rule TTP_XOR_WriteProcessMemory_082a {
  strings:
    $key_082a = { 5f 58 [2] 6d 7a [2] 6b 4f [2] 45 4f [2] 7a 53 }

  condition:
    any of them
}