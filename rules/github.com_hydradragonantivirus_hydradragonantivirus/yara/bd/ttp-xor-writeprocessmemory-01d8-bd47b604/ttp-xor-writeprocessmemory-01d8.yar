rule TTP_XOR_WriteProcessMemory_01d8 {
  strings:
    $key_01d8 = { 56 aa [2] 64 88 [2] 62 bd [2] 4c bd [2] 73 a1 }

  condition:
    any of them
}