rule TTP_XOR_WriteProcessMemory_4ad8 {
  strings:
    $key_4ad8 = { 1d aa [2] 2f 88 [2] 29 bd [2] 07 bd [2] 38 a1 }

  condition:
    any of them
}