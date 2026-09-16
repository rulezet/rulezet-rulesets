rule TTP_XOR_WriteProcessMemory_05cf {
  strings:
    $key_05cf = { 52 bd [2] 60 9f [2] 66 aa [2] 48 aa [2] 77 b6 }

  condition:
    any of them
}