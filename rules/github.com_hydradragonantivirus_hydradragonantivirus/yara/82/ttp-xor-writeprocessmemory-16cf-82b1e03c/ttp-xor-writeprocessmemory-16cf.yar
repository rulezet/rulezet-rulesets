rule TTP_XOR_WriteProcessMemory_16cf {
  strings:
    $key_16cf = { 41 bd [2] 73 9f [2] 75 aa [2] 5b aa [2] 64 b6 }

  condition:
    any of them
}