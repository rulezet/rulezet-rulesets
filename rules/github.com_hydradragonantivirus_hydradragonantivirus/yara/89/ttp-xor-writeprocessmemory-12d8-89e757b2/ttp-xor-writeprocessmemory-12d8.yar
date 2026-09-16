rule TTP_XOR_WriteProcessMemory_12d8 {
  strings:
    $key_12d8 = { 45 aa [2] 77 88 [2] 71 bd [2] 5f bd [2] 60 a1 }

  condition:
    any of them
}