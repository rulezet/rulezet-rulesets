rule TTP_XOR_WriteProcessMemory_56cf {
  strings:
    $key_56cf = { 01 bd [2] 33 9f [2] 35 aa [2] 1b aa [2] 24 b6 }

  condition:
    any of them
}