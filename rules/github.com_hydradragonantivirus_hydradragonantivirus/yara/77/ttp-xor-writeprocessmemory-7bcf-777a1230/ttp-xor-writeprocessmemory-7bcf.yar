rule TTP_XOR_WriteProcessMemory_7bcf {
  strings:
    $key_7bcf = { 2c bd [2] 1e 9f [2] 18 aa [2] 36 aa [2] 09 b6 }

  condition:
    any of them
}