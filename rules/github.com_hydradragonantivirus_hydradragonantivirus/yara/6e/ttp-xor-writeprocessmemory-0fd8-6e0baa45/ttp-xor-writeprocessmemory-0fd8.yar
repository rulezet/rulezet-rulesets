rule TTP_XOR_WriteProcessMemory_0fd8 {
  strings:
    $key_0fd8 = { 58 aa [2] 6a 88 [2] 6c bd [2] 42 bd [2] 7d a1 }

  condition:
    any of them
}