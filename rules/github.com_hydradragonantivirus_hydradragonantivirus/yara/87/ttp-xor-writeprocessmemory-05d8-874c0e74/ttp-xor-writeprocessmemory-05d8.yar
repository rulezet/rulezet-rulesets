rule TTP_XOR_WriteProcessMemory_05d8 {
  strings:
    $key_05d8 = { 52 aa [2] 60 88 [2] 66 bd [2] 48 bd [2] 77 a1 }

  condition:
    any of them
}