rule TTP_XOR_WriteProcessMemory_71d8 {
  strings:
    $key_71d8 = { 26 aa [2] 14 88 [2] 12 bd [2] 3c bd [2] 03 a1 }

  condition:
    any of them
}