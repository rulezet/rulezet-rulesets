rule TTP_XOR_WriteProcessMemory_92d8 {
  strings:
    $key_92d8 = { c5 aa [2] f7 88 [2] f1 bd [2] df bd [2] e0 a1 }

  condition:
    any of them
}