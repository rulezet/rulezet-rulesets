rule TTP_XOR_WriteProcessMemory_47d8 {
  strings:
    $key_47d8 = { 10 aa [2] 22 88 [2] 24 bd [2] 0a bd [2] 35 a1 }

  condition:
    any of them
}