rule TTP_XOR_WriteProcessMemory_f8d8 {
  strings:
    $key_f8d8 = { af aa [2] 9d 88 [2] 9b bd [2] b5 bd [2] 8a a1 }

  condition:
    any of them
}