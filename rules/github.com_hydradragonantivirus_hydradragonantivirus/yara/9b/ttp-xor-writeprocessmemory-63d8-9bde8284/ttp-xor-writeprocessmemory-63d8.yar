rule TTP_XOR_WriteProcessMemory_63d8 {
  strings:
    $key_63d8 = { 34 aa [2] 06 88 [2] 00 bd [2] 2e bd [2] 11 a1 }

  condition:
    any of them
}