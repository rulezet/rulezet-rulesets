rule TTP_XOR_WriteProcessMemory_7cd8 {
  strings:
    $key_7cd8 = { 2b aa [2] 19 88 [2] 1f bd [2] 31 bd [2] 0e a1 }

  condition:
    any of them
}