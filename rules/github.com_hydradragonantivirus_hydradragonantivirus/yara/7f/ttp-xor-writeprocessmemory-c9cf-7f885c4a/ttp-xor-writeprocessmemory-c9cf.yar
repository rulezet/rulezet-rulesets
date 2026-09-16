rule TTP_XOR_WriteProcessMemory_c9cf {
  strings:
    $key_c9cf = { 9e bd [2] ac 9f [2] aa aa [2] 84 aa [2] bb b6 }

  condition:
    any of them
}