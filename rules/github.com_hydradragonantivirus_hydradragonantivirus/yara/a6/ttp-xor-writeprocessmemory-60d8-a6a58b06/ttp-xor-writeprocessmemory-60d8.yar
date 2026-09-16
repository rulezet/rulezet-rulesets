rule TTP_XOR_WriteProcessMemory_60d8 {
  strings:
    $key_60d8 = { 37 aa [2] 05 88 [2] 03 bd [2] 2d bd [2] 12 a1 }

  condition:
    any of them
}