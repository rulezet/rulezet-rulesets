rule TTP_XOR_WriteProcessMemory_31cf {
  strings:
    $key_31cf = { 66 bd [2] 54 9f [2] 52 aa [2] 7c aa [2] 43 b6 }

  condition:
    any of them
}