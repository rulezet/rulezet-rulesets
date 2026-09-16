rule TTP_XOR_WriteProcessMemory_37cf {
  strings:
    $key_37cf = { 60 bd [2] 52 9f [2] 54 aa [2] 7a aa [2] 45 b6 }

  condition:
    any of them
}