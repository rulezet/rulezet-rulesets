rule TTP_XOR_WriteProcessMemory_72cf {
  strings:
    $key_72cf = { 25 bd [2] 17 9f [2] 11 aa [2] 3f aa [2] 00 b6 }

  condition:
    any of them
}