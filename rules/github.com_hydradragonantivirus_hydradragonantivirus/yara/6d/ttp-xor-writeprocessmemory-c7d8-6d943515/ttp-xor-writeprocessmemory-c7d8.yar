rule TTP_XOR_WriteProcessMemory_c7d8 {
  strings:
    $key_c7d8 = { 90 aa [2] a2 88 [2] a4 bd [2] 8a bd [2] b5 a1 }

  condition:
    any of them
}