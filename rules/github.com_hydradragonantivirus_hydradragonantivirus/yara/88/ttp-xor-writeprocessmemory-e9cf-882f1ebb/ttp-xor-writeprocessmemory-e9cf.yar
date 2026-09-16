rule TTP_XOR_WriteProcessMemory_e9cf {
  strings:
    $key_e9cf = { be bd [2] 8c 9f [2] 8a aa [2] a4 aa [2] 9b b6 }

  condition:
    any of them
}