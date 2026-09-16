rule TTP_XOR_WriteProcessMemory_46d8 {
  strings:
    $key_46d8 = { 11 aa [2] 23 88 [2] 25 bd [2] 0b bd [2] 34 a1 }

  condition:
    any of them
}