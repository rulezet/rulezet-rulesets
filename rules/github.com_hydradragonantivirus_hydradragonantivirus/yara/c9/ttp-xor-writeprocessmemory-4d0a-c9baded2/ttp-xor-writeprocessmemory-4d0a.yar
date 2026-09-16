rule TTP_XOR_WriteProcessMemory_4d0a {
  strings:
    $key_4d0a = { 1a 78 [2] 28 5a [2] 2e 6f [2] 00 6f [2] 3f 73 }

  condition:
    any of them
}