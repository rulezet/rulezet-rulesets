rule TTP_XOR_WriteProcessMemory_5c0a {
  strings:
    $key_5c0a = { 0b 78 [2] 39 5a [2] 3f 6f [2] 11 6f [2] 2e 73 }

  condition:
    any of them
}