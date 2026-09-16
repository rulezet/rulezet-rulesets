rule TTP_XOR_WriteProcessMemory_14cf {
  strings:
    $key_14cf = { 43 bd [2] 71 9f [2] 77 aa [2] 59 aa [2] 66 b6 }

  condition:
    any of them
}