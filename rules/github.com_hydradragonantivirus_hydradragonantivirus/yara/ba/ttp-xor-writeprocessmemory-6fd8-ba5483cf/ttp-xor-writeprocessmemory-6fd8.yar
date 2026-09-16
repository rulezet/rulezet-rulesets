rule TTP_XOR_WriteProcessMemory_6fd8 {
  strings:
    $key_6fd8 = { 38 aa [2] 0a 88 [2] 0c bd [2] 22 bd [2] 1d a1 }

  condition:
    any of them
}