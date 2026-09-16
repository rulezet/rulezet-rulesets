rule TTP_XOR_WriteProcessMemory_37d8 {
  strings:
    $key_37d8 = { 60 aa [2] 52 88 [2] 54 bd [2] 7a bd [2] 45 a1 }

  condition:
    any of them
}