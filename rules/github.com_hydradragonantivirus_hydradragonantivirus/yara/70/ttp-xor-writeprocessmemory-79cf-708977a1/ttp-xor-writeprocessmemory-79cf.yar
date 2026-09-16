rule TTP_XOR_WriteProcessMemory_79cf {
  strings:
    $key_79cf = { 2e bd [2] 1c 9f [2] 1a aa [2] 34 aa [2] 0b b6 }

  condition:
    any of them
}