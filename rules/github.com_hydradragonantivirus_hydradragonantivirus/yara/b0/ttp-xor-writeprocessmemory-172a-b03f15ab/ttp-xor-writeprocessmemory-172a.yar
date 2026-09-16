rule TTP_XOR_WriteProcessMemory_172a {
  strings:
    $key_172a = { 40 58 [2] 72 7a [2] 74 4f [2] 5a 4f [2] 65 53 }

  condition:
    any of them
}