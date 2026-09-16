rule TTP_XOR_WriteProcessMemory_3bcf {
  strings:
    $key_3bcf = { 6c bd [2] 5e 9f [2] 58 aa [2] 76 aa [2] 49 b6 }

  condition:
    any of them
}