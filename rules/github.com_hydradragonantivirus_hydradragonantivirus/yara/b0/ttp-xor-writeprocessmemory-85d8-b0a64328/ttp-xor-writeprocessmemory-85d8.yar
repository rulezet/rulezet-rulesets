rule TTP_XOR_WriteProcessMemory_85d8 {
  strings:
    $key_85d8 = { d2 aa [2] e0 88 [2] e6 bd [2] c8 bd [2] f7 a1 }

  condition:
    any of them
}