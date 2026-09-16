rule TTP_XOR_WriteProcessMemory_15cf {
  strings:
    $key_15cf = { 42 bd [2] 70 9f [2] 76 aa [2] 58 aa [2] 67 b6 }

  condition:
    any of them
}