rule TTP_XOR_WriteProcessMemory_e4d8 {
  strings:
    $key_e4d8 = { b3 aa [2] 81 88 [2] 87 bd [2] a9 bd [2] 96 a1 }

  condition:
    any of them
}