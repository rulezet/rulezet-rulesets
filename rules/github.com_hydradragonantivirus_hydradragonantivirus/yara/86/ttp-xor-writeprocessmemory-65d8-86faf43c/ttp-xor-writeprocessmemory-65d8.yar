rule TTP_XOR_WriteProcessMemory_65d8 {
  strings:
    $key_65d8 = { 32 aa [2] 00 88 [2] 06 bd [2] 28 bd [2] 17 a1 }

  condition:
    any of them
}