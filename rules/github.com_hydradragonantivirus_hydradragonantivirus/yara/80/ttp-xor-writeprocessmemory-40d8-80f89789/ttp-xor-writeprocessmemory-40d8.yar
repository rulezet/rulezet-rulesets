rule TTP_XOR_WriteProcessMemory_40d8 {
  strings:
    $key_40d8 = { 17 aa [2] 25 88 [2] 23 bd [2] 0d bd [2] 32 a1 }

  condition:
    any of them
}