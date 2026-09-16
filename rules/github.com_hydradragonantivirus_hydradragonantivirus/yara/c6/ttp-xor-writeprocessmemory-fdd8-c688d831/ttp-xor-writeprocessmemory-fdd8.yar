rule TTP_XOR_WriteProcessMemory_fdd8 {
  strings:
    $key_fdd8 = { aa aa [2] 98 88 [2] 9e bd [2] b0 bd [2] 8f a1 }

  condition:
    any of them
}