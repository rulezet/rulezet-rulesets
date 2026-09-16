rule TTP_XOR_WriteProcessMemory_53d8 {
  strings:
    $key_53d8 = { 04 aa [2] 36 88 [2] 30 bd [2] 1e bd [2] 21 a1 }

  condition:
    any of them
}