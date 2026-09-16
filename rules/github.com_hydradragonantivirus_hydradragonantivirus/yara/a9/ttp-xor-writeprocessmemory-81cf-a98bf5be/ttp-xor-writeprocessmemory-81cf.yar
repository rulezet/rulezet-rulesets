rule TTP_XOR_WriteProcessMemory_81cf {
  strings:
    $key_81cf = { d6 bd [2] e4 9f [2] e2 aa [2] cc aa [2] f3 b6 }

  condition:
    any of them
}