rule TTP_XOR_WriteProcessMemory_23cf {
  strings:
    $key_23cf = { 74 bd [2] 46 9f [2] 40 aa [2] 6e aa [2] 51 b6 }

  condition:
    any of them
}