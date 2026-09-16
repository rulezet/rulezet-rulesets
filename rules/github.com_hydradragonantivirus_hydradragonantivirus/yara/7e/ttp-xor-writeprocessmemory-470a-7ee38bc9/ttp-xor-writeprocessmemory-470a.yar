rule TTP_XOR_WriteProcessMemory_470a {
  strings:
    $key_470a = { 10 78 [2] 22 5a [2] 24 6f [2] 0a 6f [2] 35 73 }

  condition:
    any of them
}