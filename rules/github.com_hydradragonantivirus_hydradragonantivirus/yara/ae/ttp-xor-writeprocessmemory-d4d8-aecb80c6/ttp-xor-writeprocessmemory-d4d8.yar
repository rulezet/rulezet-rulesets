rule TTP_XOR_WriteProcessMemory_d4d8 {
  strings:
    $key_d4d8 = { 83 aa [2] b1 88 [2] b7 bd [2] 99 bd [2] a6 a1 }

  condition:
    any of them
}