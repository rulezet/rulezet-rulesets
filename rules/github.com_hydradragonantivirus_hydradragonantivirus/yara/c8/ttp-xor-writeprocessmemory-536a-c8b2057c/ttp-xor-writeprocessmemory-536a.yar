rule TTP_XOR_WriteProcessMemory_536a {
  strings:
    $key_536a = { 04 18 [2] 36 3a [2] 30 0f [2] 1e 0f [2] 21 13 }

  condition:
    any of them
}