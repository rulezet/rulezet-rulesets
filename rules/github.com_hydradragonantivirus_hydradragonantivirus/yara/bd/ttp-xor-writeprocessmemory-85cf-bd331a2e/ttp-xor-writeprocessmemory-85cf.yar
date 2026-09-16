rule TTP_XOR_WriteProcessMemory_85cf {
  strings:
    $key_85cf = { d2 bd [2] e0 9f [2] e6 aa [2] c8 aa [2] f7 b6 }

  condition:
    any of them
}