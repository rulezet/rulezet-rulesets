rule TTP_XOR_WriteProcessMemory_67cf {
  strings:
    $key_67cf = { 30 bd [2] 02 9f [2] 04 aa [2] 2a aa [2] 15 b6 }

  condition:
    any of them
}