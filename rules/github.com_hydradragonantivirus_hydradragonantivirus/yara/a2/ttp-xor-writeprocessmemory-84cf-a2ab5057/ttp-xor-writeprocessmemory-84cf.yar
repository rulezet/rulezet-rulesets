rule TTP_XOR_WriteProcessMemory_84cf {
  strings:
    $key_84cf = { d3 bd [2] e1 9f [2] e7 aa [2] c9 aa [2] f6 b6 }

  condition:
    any of them
}