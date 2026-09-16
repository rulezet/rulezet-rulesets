rule TTP_XOR_WriteProcessMemory_29cf {
  strings:
    $key_29cf = { 7e bd [2] 4c 9f [2] 4a aa [2] 64 aa [2] 5b b6 }

  condition:
    any of them
}