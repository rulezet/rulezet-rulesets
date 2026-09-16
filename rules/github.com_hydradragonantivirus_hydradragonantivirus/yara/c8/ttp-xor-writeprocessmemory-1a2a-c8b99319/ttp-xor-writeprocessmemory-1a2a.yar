rule TTP_XOR_WriteProcessMemory_1a2a {
  strings:
    $key_1a2a = { 4d 58 [2] 7f 7a [2] 79 4f [2] 57 4f [2] 68 53 }

  condition:
    any of them
}