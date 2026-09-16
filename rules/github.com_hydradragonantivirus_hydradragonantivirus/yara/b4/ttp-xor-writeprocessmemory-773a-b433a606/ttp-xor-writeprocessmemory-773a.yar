rule TTP_XOR_WriteProcessMemory_773a {
  strings:
    $key_773a = { 20 48 [2] 12 6a [2] 14 5f [2] 3a 5f [2] 05 43 }

  condition:
    any of them
}