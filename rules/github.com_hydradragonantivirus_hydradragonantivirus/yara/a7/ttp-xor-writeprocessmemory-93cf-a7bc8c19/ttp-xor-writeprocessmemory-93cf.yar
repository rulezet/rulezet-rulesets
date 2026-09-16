rule TTP_XOR_WriteProcessMemory_93cf {
  strings:
    $key_93cf = { c4 bd [2] f6 9f [2] f0 aa [2] de aa [2] e1 b6 }

  condition:
    any of them
}