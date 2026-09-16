rule TTP_XOR_WriteProcessMemory_0cd8 {
  strings:
    $key_0cd8 = { 5b aa [2] 69 88 [2] 6f bd [2] 41 bd [2] 7e a1 }

  condition:
    any of them
}