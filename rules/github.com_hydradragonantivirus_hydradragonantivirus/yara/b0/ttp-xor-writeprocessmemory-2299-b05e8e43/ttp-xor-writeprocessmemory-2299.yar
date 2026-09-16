rule TTP_XOR_WriteProcessMemory_2299 {
  strings:
    $key_2299 = { 75 eb [2] 47 c9 [2] 41 fc [2] 6f fc [2] 50 e0 }

  condition:
    any of them
}