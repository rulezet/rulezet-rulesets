rule TTP_XOR_WriteProcessMemory_39cf {
  strings:
    $key_39cf = { 6e bd [2] 5c 9f [2] 5a aa [2] 74 aa [2] 4b b6 }

  condition:
    any of them
}