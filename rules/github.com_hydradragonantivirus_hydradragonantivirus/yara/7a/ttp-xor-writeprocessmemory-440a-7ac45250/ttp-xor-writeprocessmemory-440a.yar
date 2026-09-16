rule TTP_XOR_WriteProcessMemory_440a {
  strings:
    $key_440a = { 13 78 [2] 21 5a [2] 27 6f [2] 09 6f [2] 36 73 }

  condition:
    any of them
}