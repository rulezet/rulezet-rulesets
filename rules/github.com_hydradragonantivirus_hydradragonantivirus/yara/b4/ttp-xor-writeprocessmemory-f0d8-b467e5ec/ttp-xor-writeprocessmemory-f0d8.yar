rule TTP_XOR_WriteProcessMemory_f0d8 {
  strings:
    $key_f0d8 = { a7 aa [2] 95 88 [2] 93 bd [2] bd bd [2] 82 a1 }

  condition:
    any of them
}