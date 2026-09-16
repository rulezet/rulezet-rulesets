rule TTP_XOR_WriteProcessMemory_07cf {
  strings:
    $key_07cf = { 50 bd [2] 62 9f [2] 64 aa [2] 4a aa [2] 75 b6 }

  condition:
    any of them
}