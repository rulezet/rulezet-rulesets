rule TTP_XOR_WriteProcessMemory_84d8 {
  strings:
    $key_84d8 = { d3 aa [2] e1 88 [2] e7 bd [2] c9 bd [2] f6 a1 }

  condition:
    any of them
}