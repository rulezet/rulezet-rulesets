rule TTP_XOR_WriteProcessMemory_12cf {
  strings:
    $key_12cf = { 45 bd [2] 77 9f [2] 71 aa [2] 5f aa [2] 60 b6 }

  condition:
    any of them
}