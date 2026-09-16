rule TTP_XOR_WriteProcessMemory_6cd8 {
  strings:
    $key_6cd8 = { 3b aa [2] 09 88 [2] 0f bd [2] 21 bd [2] 1e a1 }

  condition:
    any of them
}