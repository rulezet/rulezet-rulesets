rule TTP_XOR_WriteProcessMemory_6dd8 {
  strings:
    $key_6dd8 = { 3a aa [2] 08 88 [2] 0e bd [2] 20 bd [2] 1f a1 }

  condition:
    any of them
}