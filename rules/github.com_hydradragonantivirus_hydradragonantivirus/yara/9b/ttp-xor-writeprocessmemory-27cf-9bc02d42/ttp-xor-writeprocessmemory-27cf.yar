rule TTP_XOR_WriteProcessMemory_27cf {
  strings:
    $key_27cf = { 70 bd [2] 42 9f [2] 44 aa [2] 6a aa [2] 55 b6 }

  condition:
    any of them
}