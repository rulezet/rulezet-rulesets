rule TTP_XOR_WriteProcessMemory_c4d8 {
  strings:
    $key_c4d8 = { 93 aa [2] a1 88 [2] a7 bd [2] 89 bd [2] b6 a1 }

  condition:
    any of them
}