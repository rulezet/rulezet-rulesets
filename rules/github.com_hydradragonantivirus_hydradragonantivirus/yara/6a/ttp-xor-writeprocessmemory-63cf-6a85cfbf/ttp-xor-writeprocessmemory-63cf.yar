rule TTP_XOR_WriteProcessMemory_63cf {
  strings:
    $key_63cf = { 34 bd [2] 06 9f [2] 00 aa [2] 2e aa [2] 11 b6 }

  condition:
    any of them
}