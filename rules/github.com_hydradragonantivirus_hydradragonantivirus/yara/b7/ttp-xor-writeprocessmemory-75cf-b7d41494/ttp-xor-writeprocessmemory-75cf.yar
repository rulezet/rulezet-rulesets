rule TTP_XOR_WriteProcessMemory_75cf {
  strings:
    $key_75cf = { 22 bd [2] 10 9f [2] 16 aa [2] 38 aa [2] 07 b6 }

  condition:
    any of them
}