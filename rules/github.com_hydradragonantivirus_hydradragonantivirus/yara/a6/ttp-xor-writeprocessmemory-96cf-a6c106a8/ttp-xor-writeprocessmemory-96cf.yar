rule TTP_XOR_WriteProcessMemory_96cf {
  strings:
    $key_96cf = { c1 bd [2] f3 9f [2] f5 aa [2] db aa [2] e4 b6 }

  condition:
    any of them
}