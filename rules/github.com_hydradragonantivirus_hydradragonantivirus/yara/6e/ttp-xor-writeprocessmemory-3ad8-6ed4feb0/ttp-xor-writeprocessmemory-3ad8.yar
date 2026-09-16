rule TTP_XOR_WriteProcessMemory_3ad8 {
  strings:
    $key_3ad8 = { 6d aa [2] 5f 88 [2] 59 bd [2] 77 bd [2] 48 a1 }

  condition:
    any of them
}