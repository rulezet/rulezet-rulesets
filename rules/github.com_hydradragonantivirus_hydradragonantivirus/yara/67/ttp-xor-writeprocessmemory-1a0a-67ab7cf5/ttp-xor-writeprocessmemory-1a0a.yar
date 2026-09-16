rule TTP_XOR_WriteProcessMemory_1a0a {
  strings:
    $key_1a0a = { 4d 78 [2] 7f 5a [2] 79 6f [2] 57 6f [2] 68 73 }

  condition:
    any of them
}