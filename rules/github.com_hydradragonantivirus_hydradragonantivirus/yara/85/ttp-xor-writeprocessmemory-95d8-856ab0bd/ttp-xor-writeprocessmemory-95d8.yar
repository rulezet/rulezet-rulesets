rule TTP_XOR_WriteProcessMemory_95d8 {
  strings:
    $key_95d8 = { c2 aa [2] f0 88 [2] f6 bd [2] d8 bd [2] e7 a1 }

  condition:
    any of them
}