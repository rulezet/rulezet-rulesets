rule TTP_XOR_WriteProcessMemory_26d8 {
  strings:
    $key_26d8 = { 71 aa [2] 43 88 [2] 45 bd [2] 6b bd [2] 54 a1 }

  condition:
    any of them
}