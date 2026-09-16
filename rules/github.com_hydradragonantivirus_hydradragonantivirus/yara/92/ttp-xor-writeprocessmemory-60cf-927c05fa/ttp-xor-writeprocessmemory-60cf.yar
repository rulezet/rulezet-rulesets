rule TTP_XOR_WriteProcessMemory_60cf {
  strings:
    $key_60cf = { 37 bd [2] 05 9f [2] 03 aa [2] 2d aa [2] 12 b6 }

  condition:
    any of them
}