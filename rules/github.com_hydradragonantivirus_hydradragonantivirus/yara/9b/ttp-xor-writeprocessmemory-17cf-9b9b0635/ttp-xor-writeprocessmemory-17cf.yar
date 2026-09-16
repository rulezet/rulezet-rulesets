rule TTP_XOR_WriteProcessMemory_17cf {
  strings:
    $key_17cf = { 40 bd [2] 72 9f [2] 74 aa [2] 5a aa [2] 65 b6 }

  condition:
    any of them
}