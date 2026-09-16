rule TTP_XOR_WriteProcessMemory_33d8 {
  strings:
    $key_33d8 = { 64 aa [2] 56 88 [2] 50 bd [2] 7e bd [2] 41 a1 }

  condition:
    any of them
}