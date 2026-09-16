rule TTP_XOR_WriteProcessMemory_40cf {
  strings:
    $key_40cf = { 17 bd [2] 25 9f [2] 23 aa [2] 0d aa [2] 32 b6 }

  condition:
    any of them
}