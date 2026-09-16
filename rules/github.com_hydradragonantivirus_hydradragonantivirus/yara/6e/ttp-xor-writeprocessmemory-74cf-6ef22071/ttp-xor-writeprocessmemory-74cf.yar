rule TTP_XOR_WriteProcessMemory_74cf {
  strings:
    $key_74cf = { 23 bd [2] 11 9f [2] 17 aa [2] 39 aa [2] 06 b6 }

  condition:
    any of them
}