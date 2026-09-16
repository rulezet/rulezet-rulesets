rule TTP_XOR_WriteProcessMemory_47cf {
  strings:
    $key_47cf = { 10 bd [2] 22 9f [2] 24 aa [2] 0a aa [2] 35 b6 }

  condition:
    any of them
}