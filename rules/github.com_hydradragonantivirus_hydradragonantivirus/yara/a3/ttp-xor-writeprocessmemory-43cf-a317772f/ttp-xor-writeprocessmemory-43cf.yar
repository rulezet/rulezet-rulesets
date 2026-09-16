rule TTP_XOR_WriteProcessMemory_43cf {
  strings:
    $key_43cf = { 14 bd [2] 26 9f [2] 20 aa [2] 0e aa [2] 31 b6 }

  condition:
    any of them
}