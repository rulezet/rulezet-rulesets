rule TTP_XOR_WriteProcessMemory_65cf {
  strings:
    $key_65cf = { 32 bd [2] 00 9f [2] 06 aa [2] 28 aa [2] 17 b6 }

  condition:
    any of them
}