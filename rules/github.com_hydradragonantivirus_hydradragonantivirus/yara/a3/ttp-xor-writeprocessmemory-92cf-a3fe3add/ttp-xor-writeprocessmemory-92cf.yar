rule TTP_XOR_WriteProcessMemory_92cf {
  strings:
    $key_92cf = { c5 bd [2] f7 9f [2] f1 aa [2] df aa [2] e0 b6 }

  condition:
    any of them
}