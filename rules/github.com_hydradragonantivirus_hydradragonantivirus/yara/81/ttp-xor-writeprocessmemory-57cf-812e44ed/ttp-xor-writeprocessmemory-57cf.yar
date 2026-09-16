rule TTP_XOR_WriteProcessMemory_57cf {
  strings:
    $key_57cf = { 00 bd [2] 32 9f [2] 34 aa [2] 1a aa [2] 25 b6 }

  condition:
    any of them
}