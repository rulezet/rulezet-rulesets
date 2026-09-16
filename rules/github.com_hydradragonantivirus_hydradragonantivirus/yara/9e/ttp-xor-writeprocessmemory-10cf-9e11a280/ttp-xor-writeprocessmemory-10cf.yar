rule TTP_XOR_WriteProcessMemory_10cf {
  strings:
    $key_10cf = { 47 bd [2] 75 9f [2] 73 aa [2] 5d aa [2] 62 b6 }

  condition:
    any of them
}