rule TTP_XOR_WriteProcessMemory_2fd8 {
  strings:
    $key_2fd8 = { 78 aa [2] 4a 88 [2] 4c bd [2] 62 bd [2] 5d a1 }

  condition:
    any of them
}