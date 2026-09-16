rule TTP_XOR_WriteProcessMemory_91cf {
  strings:
    $key_91cf = { c6 bd [2] f4 9f [2] f2 aa [2] dc aa [2] e3 b6 }

  condition:
    any of them
}