rule TTP_XOR_WriteProcessMemory_e8d8 {
  strings:
    $key_e8d8 = { bf aa [2] 8d 88 [2] 8b bd [2] a5 bd [2] 9a a1 }

  condition:
    any of them
}