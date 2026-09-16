rule TTP_XOR_WriteProcessMemory_5f1a {
  strings:
    $key_5f1a = { 08 68 [2] 3a 4a [2] 3c 7f [2] 12 7f [2] 2d 63 }

  condition:
    any of them
}