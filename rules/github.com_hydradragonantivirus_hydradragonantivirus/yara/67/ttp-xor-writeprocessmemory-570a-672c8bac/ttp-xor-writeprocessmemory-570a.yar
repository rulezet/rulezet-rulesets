rule TTP_XOR_WriteProcessMemory_570a {
  strings:
    $key_570a = { 00 78 [2] 32 5a [2] 34 6f [2] 1a 6f [2] 25 73 }

  condition:
    any of them
}