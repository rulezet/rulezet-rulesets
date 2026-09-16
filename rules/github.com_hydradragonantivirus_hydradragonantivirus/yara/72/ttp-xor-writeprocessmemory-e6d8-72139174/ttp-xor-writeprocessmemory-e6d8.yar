rule TTP_XOR_WriteProcessMemory_e6d8 {
  strings:
    $key_e6d8 = { b1 aa [2] 83 88 [2] 85 bd [2] ab bd [2] 94 a1 }

  condition:
    any of them
}