rule TTP_XOR_WriteProcessMemory_25cf {
  strings:
    $key_25cf = { 72 bd [2] 40 9f [2] 46 aa [2] 68 aa [2] 57 b6 }

  condition:
    any of them
}