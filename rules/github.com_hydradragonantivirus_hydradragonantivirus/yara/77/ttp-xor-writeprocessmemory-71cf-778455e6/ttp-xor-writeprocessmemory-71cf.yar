rule TTP_XOR_WriteProcessMemory_71cf {
  strings:
    $key_71cf = { 26 bd [2] 14 9f [2] 12 aa [2] 3c aa [2] 03 b6 }

  condition:
    any of them
}